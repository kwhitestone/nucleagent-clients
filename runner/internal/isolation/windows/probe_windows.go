//go:build windows

package isolation

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

type ProbeResult struct {
	ExecutableSHA256                  string
	BrokerLoopbackOK                  bool
	CleanupError                      string
	ActiveProcessesAfterCleanup       uint32
	SessionResponses                  []json.RawMessage
	SessionError                      string
	LoaderTrace                       []string
	Time, Mode, Root, Stage, Error    string
	SID                               string
	Parent, Child                     TokenEvidence
	PID                               uint32
	InJob, Resumed, TimedOut          bool
	ExitCode                          uint32
	Job                               windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	CPUFlags, CPURate, UIRestrictions uint32
	Desktop                           string
	Stdout, Stderr                    string
	Access                            []AccessObservation
	Profile, ProfileCleanupError      string
}

// Probe is deliberately separate from platform.Start. A failed feasibility
// probe cannot silently enable ordinary-user execution or a weaker policy.
func Probe(base, executable string, args []string, safer, appContainer, trace, session, internetClient bool) (result ProbeResult) {
	result.Time = time.Now().UTC().Format(time.RFC3339Nano)
	result.Mode = "restricted-token"
	if safer {
		result.Mode = "safer-constrained+restricted-token"
	}
	if appContainer {
		result.Mode = "appcontainer+privilege-restricted-token"
		if internetClient {
			result.Mode += "+internetClient"
		}
	}
	err := probe(base, executable, args, safer, appContainer, trace, session, internetClient, &result)
	if err != nil {
		result.Error = err.Error()
	}
	if result.CleanupError != "" || result.ProfileCleanupError != "" {
		result.Error += " cleanup: " + result.CleanupError + " " + result.ProfileCleanupError
	}
	return
}

func probe(base, executable string, args []string, safer, appContainer, trace, session, internetClient bool, result *ProbeResult) error {
	if trace {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
	}
	result.Stage = "prepare"
	if err := checkPath(base); err != nil {
		return err
	}
	var err error
	result.Parent, err = InspectToken(windows.GetCurrentProcessToken())
	if err != nil {
		return err
	}
	sid, err := newSID()
	if err != nil {
		return err
	}
	if appContainer {
		name, _ := windows.UTF16PtrFromString("na." + strings.TrimPrefix(sid.String(), "S-1-5-21-"))
		var packageSID *windows.SID
		userenv := windows.NewLazySystemDLL("userenv.dll")
		hr, _, _ := userenv.NewProc("CreateAppContainerProfile").Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(name)), 0, 0, uintptr(unsafe.Pointer(&packageSID)))
		if int32(hr) < 0 {
			return fmt.Errorf("CreateAppContainerProfile HRESULT 0x%08x", uint32(hr))
		}
		defer func() {
			hr, _, _ := userenv.NewProc("DeleteAppContainerProfile").Call(uintptr(unsafe.Pointer(name)))
			if int32(hr) < 0 {
				result.ProfileCleanupError = fmt.Sprintf("HRESULT 0x%08x", uint32(hr))
			}
		}()
		defer windows.FreeSid(packageSID)
		sid = packageSID
		sidText, _ := windows.UTF16PtrFromString(sid.String())
		var folder *uint16
		hr, _, _ = userenv.NewProc("GetAppContainerFolderPath").Call(uintptr(unsafe.Pointer(sidText)), uintptr(unsafe.Pointer(&folder)))
		if int32(hr) < 0 {
			return fmt.Errorf("GetAppContainerFolderPath HRESULT 0x%08x", uint32(hr))
		}
		result.Profile = windows.UTF16PtrToString(folder)
		windows.NewLazySystemDLL("ole32.dll").NewProc("CoTaskMemFree").Call(uintptr(unsafe.Pointer(folder)))
		// Seal this new disposable profile: no outside-task write exemption.
		if err = filepath.Walk(filepath.Dir(result.Profile), func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if err = checkPath(path); err != nil {
				return err
			}
			return SetProbeACL(path, sid.String(), false)
		}); err != nil {
			return err
		}
	}
	result.SID = sid.String()
	root, err := os.MkdirTemp(base, "native-")
	if err != nil {
		return err
	}
	result.Root = root
	if err = SetProbeACL(root, result.SID, false); err != nil {
		return err
	}
	for _, dir := range []string{"workspace", "home", "tmp", "runtime", "control"} {
		path := filepath.Join(root, dir)
		if err = os.Mkdir(path, 0700); err != nil {
			return err
		}
		aclSID := result.SID
		if dir == "control" {
			aclSID = ""
		}
		if err = SetProbeACL(path, aclSID, dir == "workspace" || dir == "home" || dir == "tmp"); err != nil {
			return err
		}
	}
	appPath := filepath.Join(root, "runtime", filepath.Base(executable))
	if err = copyProbeFile(executable, appPath); err != nil {
		return err
	}
	binary, readErr := os.ReadFile(appPath)
	if readErr != nil {
		return readErr
	}
	result.ExecutableSHA256 = fmt.Sprintf("%x", sha256.Sum256(binary))
	if err = SetProbeACL(appPath, result.SID, false); err != nil {
		return err
	}
	if len(args) == 1 && args[0] == "-child" {
		outside, err := os.MkdirTemp(base, "outside-")
		if err != nil {
			return err
		}
		if err = SetProbeACL(outside, "", false); err != nil {
			return err
		}
		for _, d := range []string{"sibling-task", "public-low"} {
			if err = os.Mkdir(filepath.Join(outside, d), 0700); err != nil {
				return err
			}
		}
		if err = SetProbeACL(filepath.Join(outside, "public-low"), "S-1-1-0", true); err != nil {
			return err
		}
		for _, p := range []string{filepath.Join(outside, "sensitive-canary.txt"), filepath.Join(outside, "sibling-task", "sentinel.txt"), filepath.Join(root, "control", "sensitive-canary.txt")} {
			if err = os.WriteFile(p, []byte("synthetic canary, not a credential"), 0600); err != nil {
				return err
			}
		}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return err
		}
		defer listener.Close()
		go func() {
			for {
				c, err := listener.Accept()
				if err != nil {
					return
				}
				c.Write([]byte("ok"))
				c.Close()
			}
		}()
		check, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
		if err != nil {
			return err
		}
		check.SetDeadline(time.Now().Add(time.Second))
		reply := make([]byte, 2)
		_, err = io.ReadFull(check, reply)
		check.Close()
		if err != nil {
			return err
		}
		result.BrokerLoopbackOK = string(reply) == "ok"
		if !result.BrokerLoopbackOK {
			return fmt.Errorf("broker loopback fixture failed")
		}
		plan := childPlan{root, outside, result.Profile, listener.Addr().String()}
		b, err := json.Marshal(plan)
		if err != nil {
			return err
		}
		planPath := filepath.Join(root, "runtime", "plan.json")
		if err = os.WriteFile(planPath, b, 0600); err != nil {
			return err
		}
		args = append(args, "-plan", planPath)
	}
	result.Stage = "token"
	tokenSID := sid
	expectedSID := result.SID
	if appContainer {
		tokenSID = nil
		expectedSID = ""
	}
	token, err := restrictedToken(tokenSID, safer)
	if err != nil {
		return err
	}
	defer token.Close()
	result.Child, err = InspectToken(token)
	if err != nil {
		return err
	}
	if err = verifyToken(result.Child, expectedSID); err != nil {
		return err
	}
	if !appContainer {
		result.Access, err = accessProbe(token, root)
		if err != nil {
			return err
		}
	}
	result.Stage = "desktop"
	desk, err := privateDesktop(result.SID)
	if err != nil {
		return err
	}
	defer func() {
		if err := desk.close(); err != nil {
			result.CleanupError += " desktop: " + err.Error()
		}
	}()
	result.Desktop = desk.name
	result.Stage = "job"
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS | windows.JOB_OBJECT_LIMIT_JOB_MEMORY
	limits.BasicLimitInformation.ActiveProcessLimit = 8
	limits.JobMemoryLimit = 512 << 20
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return err
	}
	cpu := struct{ Flags, Rate uint32 }{5, 2000}
	if _, err = windows.SetInformationJobObject(job, 15, uintptr(unsafe.Pointer(&cpu)), 8); err != nil {
		return err
	}
	ui := uint32(0xde) // private desktop plus clipboard/system/display/exit/desktop restrictions
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectBasicUIRestrictions, uintptr(unsafe.Pointer(&ui)), 4); err != nil {
		return err
	}
	result.Stage = "stdio"
	var sessionInput *os.File
	if session {
		args = []string{"app-server", "--listen", "stdio://", "-c", `model_provider="nucleagent_probe"`, "-c", `model_providers.nucleagent_probe.name="Isolation fixture"`, "-c", `model_providers.nucleagent_probe.base_url="http://127.0.0.1:1/v1"`, "-c", `model_providers.nucleagent_probe.wire_api="responses"`, "-c", `model_providers.nucleagent_probe.requires_openai_auth=false`, "-c", `features.multi_agent=false`, "-c", `analytics.enabled=false`}
	}

	var files []*os.File
	defer func() {
		for _, f := range files {
			f.Close()
		}
	}()
	for _, name := range []string{"stdin", "stdout", "stderr"} {
		f, er := os.OpenFile(filepath.Join(root, "control", name), os.O_CREATE|os.O_RDWR|os.O_EXCL, 0600)
		if er != nil {
			return er
		}
		files = append(files, f)
	}
	if session {
		inR, inW, err := os.Pipe()
		if err != nil {
			return err
		}
		files[0].Close()
		files[0] = inR
		sessionInput = inW
		defer inW.Close()
	}
	var handles []windows.Handle
	defer func() {
		for _, h := range handles {
			windows.CloseHandle(h)
		}
	}()
	for _, f := range files {
		var h windows.Handle
		if err = windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(f.Fd()), windows.CurrentProcess(), &h, 0, true, windows.DUPLICATE_SAME_ACCESS); err != nil {
			return err
		}
		handles = append(handles, h)
	}
	attrCount := uint32(2)
	if appContainer {
		attrCount++
	}
	attrs, err := windows.NewProcThreadAttributeList(attrCount)
	if err != nil {
		return err
	}
	defer attrs.Delete()
	caps := struct {
		SID             *windows.SID
		Capabilities    *windows.SIDAndAttributes
		Count, Reserved uint32
	}{SID: sid}
	var internet windows.SIDAndAttributes
	if internetClient {
		capSID, er := windows.StringToSid("S-1-15-3-1")
		if er != nil {
			return er
		}
		internet = windows.SIDAndAttributes{Sid: capSID, Attributes: windows.SE_GROUP_ENABLED}
		caps.Capabilities = &internet
		caps.Count = 1
	}
	if appContainer {
		if err = attrs.Update(0x00020009, unsafe.Pointer(&caps), unsafe.Sizeof(caps)); err != nil {
			return err
		}
	}
	if err = attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		return err
	}
	const jobList = 0x0002000d
	if err = attrs.Update(jobList, unsafe.Pointer(&job), unsafe.Sizeof(job)); err != nil {
		return err
	}
	si := windows.StartupInfoEx{}
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESTDHANDLES
	si.StdInput = handles[0]
	si.StdOutput = handles[1]
	si.StdErr = handles[2]
	si.ProcThreadAttributeList = attrs.List()
	si.Desktop, err = windows.UTF16PtrFromString(desk.name)
	if err != nil {
		return err
	}
	argv := []string{windows.EscapeArg(appPath)}
	for _, arg := range args {
		argv = append(argv, windows.EscapeArg(arg))
	}
	command, err := windows.UTF16PtrFromString(strings.Join(argv, " "))
	if err != nil {
		return err
	}
	app, err := windows.UTF16PtrFromString(appPath)
	if err != nil {
		return err
	}
	cwd, err := windows.UTF16PtrFromString(filepath.Join(root, "workspace"))
	if err != nil {
		return err
	}
	system, err := windows.GetWindowsDirectory()
	if err != nil {
		return err
	}
	env := []string{"SystemRoot=" + system, "WINDIR=" + system, "PATH=" + filepath.Join(system, "System32"), "HOME=" + filepath.Join(root, "home"), "USERPROFILE=" + filepath.Join(root, "home"), "CODEX_HOME=" + filepath.Join(root, "home"), "TEMP=" + filepath.Join(root, "tmp"), "TMP=" + filepath.Join(root, "tmp")}
	env = append(env, "LOCALAPPDATA="+filepath.Join(root, "home"), "APPDATA="+filepath.Join(root, "home"))
	sort.Strings(env)
	block := utf16.Encode([]rune(strings.Join(env, "\x00") + "\x00\x00"))
	pi := windows.ProcessInformation{}
	result.Stage = "create-suspended"
	flags := uint32(windows.CREATE_SUSPENDED | windows.DETACHED_PROCESS | windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT)
	if trace {
		flags |= 2
	}
	if err = windows.CreateProcessAsUser(token, app, command, nil, nil, true, flags, &block[0], cwd, &si.StartupInfo, &pi); err != nil {
		return err
	}
	defer windows.CloseHandle(pi.Thread)
	defer windows.CloseHandle(pi.Process)
	defer func() {
		if err := windows.TerminateJobObject(job, 1); err != nil {
			result.CleanupError = err.Error()
			return
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			var accounting struct {
				Times                                                            [4]int64
				PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses uint32
			}
			if err := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&accounting)), uint32(unsafe.Sizeof(accounting)), nil); err != nil {
				result.CleanupError = err.Error()
				return
			}
			result.ActiveProcessesAfterCleanup = accounting.ActiveProcesses
			if accounting.ActiveProcesses == 0 {
				return
			}
			if time.Now().After(deadline) {
				result.CleanupError = "job cleanup timed out"
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	result.PID = pi.ProcessId
	result.Stage = "verify-suspended"
	var childToken windows.Token
	if err = windows.OpenProcessToken(pi.Process, windows.TOKEN_QUERY, &childToken); err != nil {
		return err
	}
	result.Child, err = InspectToken(childToken)
	childToken.Close()
	if err != nil {
		return err
	}
	if err = verifyToken(result.Child, result.SID); err != nil {
		return err
	}
	var inJob int32
	r, _, er := windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob").Call(uintptr(pi.Process), uintptr(job), uintptr(unsafe.Pointer(&inJob)))
	if r == 0 {
		return er
	}
	result.InJob = inJob != 0
	if !result.InJob {
		return fmt.Errorf("child not in job before resume")
	}
	if err = windows.QueryInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&result.Job)), uint32(unsafe.Sizeof(result.Job)), nil); err != nil {
		return err
	}
	if result.Job.BasicLimitInformation.LimitFlags != limits.BasicLimitInformation.LimitFlags || result.Job.BasicLimitInformation.ActiveProcessLimit != 8 || result.Job.JobMemoryLimit != 512<<20 {
		return fmt.Errorf("job policy mismatch")
	}
	if err = windows.QueryInformationJobObject(job, 15, uintptr(unsafe.Pointer(&cpu)), 8, nil); err != nil {
		return err
	}
	result.CPUFlags = cpu.Flags
	result.CPURate = cpu.Rate
	if err = windows.QueryInformationJobObject(job, windows.JobObjectBasicUIRestrictions, uintptr(unsafe.Pointer(&ui)), 4, nil); err != nil {
		return err
	}
	result.UIRestrictions = ui
	if cpu.Flags != 5 || cpu.Rate != 2000 || ui != 0xde {
		return fmt.Errorf("CPU/UI policy mismatch")
	}
	result.Stage = "resume"
	if trace {
		if err = loaderSnaps(pi.Process); err != nil {
			return err
		}
	}
	if _, err = windows.ResumeThread(pi.Thread); err != nil {
		return err
	}
	result.Resumed = true
	if session {
		responses, err := sessionProbe(sessionInput, pi.Process, root)
		result.SessionResponses = responses
		if err != nil {
			result.SessionError = err.Error()
		}
		sessionInput.Close()
	}

	if trace {
		if err = debugWait(pi.Process, result); err != nil {
			return err
		}
	}
	wait, err := windows.WaitForSingleObject(pi.Process, 15000)
	if err != nil {
		return err
	}
	if wait == uint32(windows.WAIT_TIMEOUT) {
		result.TimedOut = true
		return fmt.Errorf("probe timed out")
	}
	if err = windows.GetExitCodeProcess(pi.Process, &result.ExitCode); err != nil {
		return err
	}
	for i, dst := range []*string{&result.Stdout, &result.Stderr} {
		b, er := os.ReadFile(filepath.Join(root, "control", []string{"stdout", "stderr"}[i]))
		if er != nil {
			return er
		}
		*dst = string(b)
	}
	result.Stage = "exited"
	if result.ExitCode != 0 {
		return fmt.Errorf("native child exited 0x%08x", result.ExitCode)
	}
	if result.SessionError != "" {
		return fmt.Errorf("session: %s", result.SessionError)
	}
	return nil
}
