//go:build windows

// windows-isolation-probe runs only disposable, credential-free native probes.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	isolation "nucleagent-desktop-runner/internal/isolation/windows"
)

func main() {
	base := flag.String("base", "", "existing disposable local NTFS probe directory")
	exe := flag.String("exe", "", "binary to copy into read-only probe runtime (default self)")
	safer := flag.Bool("safer", false, "compare SAFER constrained token before full restrictions")
	appContainer := flag.Bool("appcontainer", false, "probe bare Win32 AppContainer with a disposable read-only profile")
	child := flag.Bool("child", false, "internal child probe")
	descendant := flag.Bool("descendant", false, "internal descendant probe")
	trace := flag.Bool("loader-trace", false, "x64 loader diagnostic; not acceptance")
	plan := flag.String("plan", "", "internal read-only child plan")
	session := flag.Bool("session", false, "Codex empty session, no inference; requires -exe")
	internet := flag.Bool("internet-client", false, "explicit AppContainer internetClient capability experiment")
	ntHome := flag.Bool("nt-home", false, "diagnostic: use NT GLOBALROOT form for task environment paths")
	homeMode := flag.String("home-mode", "dos", "diagnostic CODEX_HOME: dos, prewarm, prewarm-copy, slash, extended, short, profile, profile-write, profile-default, junction, symlink, unset, empty")
	capNames := flag.String("capabilities", "", "diagnostic allowlisted capability names, comma-separated")
	lpac := flag.Bool("lpac", false, "diagnostic Less Privileged AppContainer")
	basic := flag.Bool("basic-token", false, "B' diagnostic: drop privileges/high groups, Low IL, no restricting SID; never production admission")
	flag.Parse()
	if *child {
		if err := isolation.ChildProbe(*plan, *descendant); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if *base == "" {
		fmt.Fprintln(os.Stderr, "-base required")
		os.Exit(2)
	}
	if *session && (*exe == "" || *trace) {
		fmt.Fprintln(os.Stderr, "session requires explicit Codex binary and no loader trace")
		os.Exit(2)
	}
	if *internet && !*appContainer {
		fmt.Fprintln(os.Stderr, "internet-client requires appcontainer")
		os.Exit(2)
	}
	args := flag.Args()
	if *exe == "" {
		var err error
		*exe, err = os.Executable()
		if err != nil {
			panic(err)
		}
		args = []string{"-child"}
	}
	if *safer && *appContainer {
		fmt.Fprintln(os.Stderr, "select one explicit candidate")
		os.Exit(2)
	}
	var names []string
	if *capNames != "" {
		names = strings.Split(*capNames, ",")
	}
	result := isolation.ProbeHome(*base, *exe, args, *safer, *appContainer, *trace, *session, *internet, *ntHome, *homeMode, isolation.CompatibilityOptions{Capabilities: names, LPAC: *lpac, BasicToken: *basic})
	json.NewEncoder(os.Stdout).Encode(result)
	if result.Error != "" {
		os.Exit(1)
	}
}
