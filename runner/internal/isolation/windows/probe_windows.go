//go:build windows

package isolation

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

type ProbeResult struct {
	CompatibilityOptions
	CapabilitySIDs                    []string
	BasicPathSecurity                 map[string]string
	Prewarm                           *PrewarmEvidence
	HomeMode, CodexHome               string
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
	ProfileHome, ProfileHomeACL       string
	RelayRequests                     int32
}

// Probe is deliberately separate from platform.Start. A failed feasibility
// probe cannot silently enable ordinary-user execution or a weaker policy.
func Probe(base, executable string, args []string, safer, appContainer, trace, session, internetClient bool, ntHome ...bool) (result ProbeResult) {
	return ProbeHome(base, executable, args, safer, appContainer, trace, session, internetClient, len(ntHome) == 1 && ntHome[0], "dos")
}

// ProbeHome varies only a disposable diagnostic's home resolution. It does not
// change production admission or authorize reparse points in task paths.
func ProbeHome(base, executable string, args []string, safer, appContainer, trace, session, internetClient, ntHome bool, homeMode string, options ...CompatibilityOptions) (result ProbeResult) {
	if len(options) == 1 {
		result.CompatibilityOptions = options[0]
	}
	if result.BasicToken && (appContainer || safer || trace || internetClient || ntHome || homeMode != "dos" || result.LPAC || len(result.Capabilities) != 0) {
		result.Error = "basic token probe cannot combine with other candidates or home workarounds"
		return
	}
	if len(options) > 1 || ((!appContainer || internetClient) && (result.LPAC || len(result.Capabilities) > 0)) {
		result.Error = "compatibility options require AppContainer without internetClient"
		return
	}
	result.HomeMode = homeMode
	result.Time = time.Now().UTC().Format(time.RFC3339Nano)
	result.Mode = "restricted-token"
	if result.BasicToken {
		result.Mode = "basic-token+low-il+private-desktop+job"
	}
	if safer {
		result.Mode = "safer-constrained+restricted-token"
	}
	if appContainer {
		result.Mode = "appcontainer+privilege-restricted-token"
		if internetClient {
			result.Mode += "+internetClient"
		}
	}
	err := probe(base, executable, args, safer, appContainer, trace, session, internetClient, ntHome, &result)
	if err != nil {
		result.Error = err.Error()
	}
	if result.CleanupError != "" || result.ProfileCleanupError != "" {
		result.Error += " cleanup: " + result.CleanupError + " " + result.ProfileCleanupError
	}
	return
}

func probe(base, executable string, args []string, safer, appContainer, trace, session, internetClient, ntHome bool, result *ProbeResult) error {
	if trace {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
	}
	result.Stage = "prepare"
	if err := checkPath(base); err != nil {
		return err
	}
	var err error
	result.Parent, err = inspectProbeToken(windows.GetCurrentProcessToken())
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
		if result.HomeMode == "profile-write" || result.HomeMode == "profile-default" {
			// The sole authorized outside-task writable subtree. Its parent and
			// all other package-profile directories stay read-only.
			result.ProfileHome = filepath.Join(result.Profile, ".codex")
			if err = os.Mkdir(result.ProfileHome, 0700); err != nil {
				return err
			}
			if err = checkPath(result.ProfileHome); err != nil {
				return err
			}
			if err = SetProbeACL(result.ProfileHome, sid.String(), true); err != nil {
				return err
			}
			sd, er := windows.GetNamedSecurityInfo(result.ProfileHome, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.LABEL_SECURITY_INFORMATION)
			if er != nil {
				return er
			}
			result.ProfileHomeACL = sd.String()
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
	for _, dir := range []string{"workspace", "home", "tmp", "runtime", "control", "cache", "config", "data"} {
		path := filepath.Join(root, dir)
		if err = os.Mkdir(path, 0700); err != nil {
			return err
		}
		aclSID := result.SID
		if dir == "control" {
			aclSID = ""
		}
		if err = SetProbeACL(path, aclSID, dir != "runtime" && dir != "control"); err != nil {
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
		aapPath := filepath.Join(root, "runtime", "aap-only.txt")
		if err = os.WriteFile(aapPath, []byte("synthetic AAP-only LPAC discriminator"), 0600); err != nil {
			return err
		}
		if err = SetProbeACL(aapPath, "S-1-15-2-1", false); err != nil {
			return err
		}
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
		if result.BasicToken {
			if err = prepareBasicDeniedCanary(filepath.Join(outside, "acl-denied-low")); err != nil {
				return err
			}
			result.BasicPathSecurity = make(map[string]string)
			for _, path := range []string{root, filepath.Join(root, "workspace"), filepath.Join(root, "runtime"), filepath.Join(root, "control"), outside, filepath.Join(outside, "public-low"), filepath.Join(outside, "acl-denied-low"), filepath.Join(outside, "acl-denied-low", "outside.txt")} {
				sd, er := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.LABEL_SECURITY_INFORMATION)
				if er != nil {
					return er
				}
				result.BasicPathSecurity[path] = sd.String()
			}
		}
		plan := childPlan{Root: root, Outside: outside, Profile: result.Profile, ProfileHome: result.ProfileHome, Loopback: listener.Addr().String(), BasicToken: result.BasicToken}
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
	if appContainer || result.BasicToken {
		tokenSID = nil
		expectedSID = ""
	}
	token, err := restrictedToken(tokenSID, safer)
	if err != nil {
		return err
	}
	defer token.Close()
	result.Child, err = inspectProbeToken(token)
	if err != nil {
		return err
	}
	if err = verifyToken(result.Child, expectedSID); err != nil {
		return err
	}
	if result.BasicToken {
		if err = verifyBasicToken(result.Child); err != nil {
			return err
		}
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
	if result.BasicToken {
		limits.BasicLimitInformation.ActiveProcessLimit = 64
		limits.JobMemoryLimit = 2 << 30
	}
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
	if appContainer && len(args) > 0 && args[0] == "-child" && !internetClient {
		var count atomic.Int32
		fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" || r.URL.Path != "/v1/responses" || r.Header.Get("Authorization") != "Bearer fixture-upstream-only" {
				http.Error(w, "scope mismatch", 403)
				return
			}
			count.Add(1)
			_, _ = io.WriteString(w, "fixture-relay-ok")
		}))
		defer fixture.Close()
		relay, err := StartRelay(context.Background(), result.SID, job, fixture.URL+"/v1", "fixture-upstream-only")
		if err != nil {
			return err
		}
		defer func() { relay.Close(); result.RelayRequests = count.Load() }()
		path := filepath.Join(root, "runtime", "plan.json")
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var plan childPlan
		if err = json.Unmarshal(b, &plan); err != nil {
			return err
		}
		plan.RelayPipe, plan.RelayToken = relay.Pipe, relay.Token
		b, err = json.Marshal(plan)
		if err != nil {
			return err
		}
		if err = os.WriteFile(path, b, 0600); err != nil {
			return err
		}
	}
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
	if result.LPAC {
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
		if len(result.Capabilities) > 0 {
			capList, er := compatibilityCapabilities(result.Capabilities)
			if er != nil {
				return er
			}
			caps.Capabilities = &capList[0]
			caps.Count = uint32(len(capList))
			for _, cap := range capList {
				result.CapabilitySIDs = append(result.CapabilitySIDs, cap.Sid.String())
			}
			defer runtime.KeepAlive(capList)
		}
		if err = attrs.Update(0x00020009, unsafe.Pointer(&caps), unsafe.Sizeof(caps)); err != nil {
			return err
		}
	}
	if result.LPAC {
		optOut := uint32(1)
		// ProcThreadAttributeAllApplicationPackagesPolicy = 15 (WinBase.h).
		if err = attrs.Update(0x0002000f, unsafe.Pointer(&optOut), unsafe.Sizeof(optOut)); err != nil {
			return err
		}
		defer runtime.KeepAlive(&optOut)
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
	env = append(env, "LOCALAPPDATA="+filepath.Join(root, "data"), "APPDATA="+filepath.Join(root, "config"))
	env = append(env, "TMPDIR="+filepath.Join(root, "tmp"), "XDG_CACHE_HOME="+filepath.Join(root, "cache"), "XDG_CONFIG_HOME="+filepath.Join(root, "config"), "XDG_DATA_HOME="+filepath.Join(root, "data"))
	if ntHome {
		p, _ := windows.UTF16PtrFromString(root)
		h, err := windows.CreateFile(p, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			return err
		}
		var b [32768]uint16
		_, err = windows.GetFinalPathNameByHandle(h, &b[0], uint32(len(b)), 2)
		windows.CloseHandle(h)
		if err != nil {
			return err
		}
		ntRoot := `\\?\GLOBALROOT` + windows.UTF16ToString(b[:])
		for i := range env {
			env[i] = strings.ReplaceAll(env[i], root, ntRoot)
		}
	}
	env, err = probeHomeEnvironment(env, root, result)
	if err != nil {
		return err
	}
	if strings.HasPrefix(result.HomeMode, "prewarm") {
		if !session {
			return fmt.Errorf("prewarm requires credential-free session probe")
		}
		result.Prewarm, err = prewarmHome(appPath, args, env, root, result.SID, result.HomeMode == "prewarm-copy")
		if err != nil {
			return err
		}
	}
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
	result.Child, err = inspectProbeToken(childToken)
	childToken.Close()
	if err != nil {
		return err
	}
	if err = verifyCompatibilityToken(result.Child, result); err != nil {
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
	if result.Job.BasicLimitInformation.LimitFlags != limits.BasicLimitInformation.LimitFlags || result.Job.BasicLimitInformation.ActiveProcessLimit != limits.BasicLimitInformation.ActiveProcessLimit || result.Job.JobMemoryLimit != limits.JobMemoryLimit {
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
	if result.BasicToken && len(args) > 0 && args[0] == "-child" {
		return verifyBasicBoundary(result)
	}
	if appContainer && !internetClient && len(args) > 0 && args[0] == "-child" {
		var evidence childEvidence
		if err = json.Unmarshal([]byte(result.Stdout), &evidence); err != nil {
			return err
		}
		if evidence.Descendant == nil {
			return fmt.Errorf("descendant evidence missing")
		}
		for _, e := range []*childEvidence{&evidence, evidence.Descendant} {
			if err = verifyCompatibilityToken(e.Token, result); err != nil {
				return err
			}
			if !e.InJob || !e.RelayOK || !e.RelayBadTokenRejected || !e.RelayRouteRejected || !e.TaskHTTPRelayOK || !e.RelayInstanceDenied || !e.RelayACLDenied {
				return fmt.Errorf("relay boundary probe failed")
			}
		}
	}
	return nil
}
