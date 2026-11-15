package main

// The root-only subcommands: checkpoint, confirm, undo (the undo net; status is in check.go) and allow, disallow, allowed
// (the server-side key of the two-key rule).

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"time"
)

func cmdCheckpoint(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "--session" {
		return cmdSessionCheckpoint(args, stdout, stderr) // securemyserver-gate's form (session.go), checked exactly
	}
	fs := flag.NewFlagSet("securemyserver checkpoint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	minutes := fs.Int("minutes", 5, "restore automatically after this many minutes unless confirmed (1 to 60)")
	reason := fs.String("reason", "", "a short note saved with the checkpoint")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: sudo securemyserver checkpoint [--minutes 5] [--reason TEXT] %s...\n", strings.Join(targetOrder, "|"))
	}
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return 2
	}
	if *minutes < 1 || *minutes > 60 {
		fmt.Fprintln(stderr, "securemyserver checkpoint: --minutes must be 1 to 60")
		return 2
	}
	targets, err := parseTargets(fs.Args())
	if err != nil {
		fmt.Fprintln(stderr, "securemyserver checkpoint:", err)
		fs.Usage()
		return 2
	}
	if err := requireRoot(); err != nil {
		fmt.Fprintln(stderr, "securemyserver checkpoint:", err)
		return 1
	}
	var m *Manifest
	err = withLock(func() error {
		var err error
		m, err = createCheckpoint(targets, time.Duration(*minutes)*time.Minute, orDefault(*reason, "securemyserver checkpoint"))
		return err
	})
	if err != nil {
		fmt.Fprintln(stderr, "securemyserver checkpoint:", err)
		return 1
	}
	files := 0
	for _, e := range m.Entries {
		if e.Kind == "file" {
			files++
		}
	}
	fmt.Fprintf(stderr, "Checkpoint %s saved: %s (%d files).\n", m.ID, strings.Join(m.Targets, ", "), files)
	fmt.Fprintf(stderr, "It restores itself at %s (in %d min) unless you confirm.\n", m.Deadline.Format("15:04:05 UTC"), *minutes)
	fmt.Fprintln(stderr, "When a NEW SSH login works, confirm from that new session: sudo securemyserver confirm")
	fmt.Fprintln(stderr, "To restore now:                                          sudo securemyserver undo")
	if m.Timer == "" {
		fmt.Fprintln(stderr, "Note: no systemd here, so only a running `securemyserver agent` restores it at the deadline.")
	}
	fmt.Fprintln(stdout, cpPath(m.ID)) // the folder, for scripts: C=$(sudo securemyserver checkpoint ssh)
	return 0
}

// reorderFlags lets flags follow the targets: `checkpoint ssh ufw --minutes 10`.
func reorderFlags(args []string) []string {
	var flags, rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			if !strings.Contains(a, "=") && !isBoolFlag(a) && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		rest = append(rest, a)
	}
	return append(flags, rest...)
}

func isBoolFlag(a string) bool {
	a = strings.TrimLeft(a, "-")
	return a == "allow-same-session" || a == "h" || a == "help"
}

func orDefault(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

func pickCheckpoint(id string, statuses ...string) (*Manifest, error) {
	if id != "" {
		return loadManifest(id)
	}
	all := listCheckpoints()
	for i := len(all) - 1; i >= 0; i-- {
		if has(statuses, all[i].Status) {
			return all[i], nil
		}
	}
	return nil, fmt.Errorf("no %s checkpoint", strings.Join(statuses, " or "))
}

func cmdConfirm(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("securemyserver confirm", flag.ContinueOnError)
	fs.SetOutput(stderr)
	same := fs.Bool("allow-same-session", false, "confirm from the session that made the checkpoint (not recommended)")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return 2
	}
	if err := requireRoot(); err != nil {
		fmt.Fprintln(stderr, "securemyserver confirm:", err)
		return 1
	}
	var out string
	err := withLock(func() error {
		m, err := pickCheckpoint(fs.Arg(0), cpPending)
		if err != nil {
			return err
		}
		if cur := auditSession(); !*same && m.Session != "" && cur == m.Session {
			return fmt.Errorf("this is the session that made checkpoint %s. Confirm from a NEW SSH login: that proves you can still get in (or add --allow-same-session)", m.ID)
		}
		if err := confirmCheckpoint(m, "securemyserver confirm"); err != nil {
			return err
		}
		out = fmt.Sprintf("Confirmed %s. The change stays; it will not be restored.", m.ID)
		return nil
	})
	if err != nil {
		fmt.Fprintln(stderr, "securemyserver confirm:", err)
		return 1
	}
	fmt.Fprintln(stdout, out)
	return 0
}

func cmdUndo(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("securemyserver undo", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ifPending := fs.String("if-pending", "", "only restore this checkpoint if it is still waiting and its deadline passed (used by the timer)")
	if err := fs.Parse(reorderFlags(args)); err != nil {
		return 2
	}
	if err := requireRoot(); err != nil {
		fmt.Fprintln(stderr, "securemyserver undo:", err)
		return 1
	}
	var out string
	err := withLock(func() error {
		if *ifPending != "" {
			m, err := loadManifest(*ifPending)
			if err != nil {
				return err
			}
			if m.Status != cpPending || nowFn().Add(5*time.Second).Before(m.Deadline) {
				out = fmt.Sprintf("Checkpoint %s is %s: nothing to do.", m.ID, m.Status)
				return nil
			}
			if err := restoreCheckpoint(m, "deadline passed without a confirm (systemd timer)"); err != nil {
				return err
			}
			out = fmt.Sprintf("Restored checkpoint %s at its deadline.", m.ID)
			return nil
		}
		m, err := pickCheckpoint(fs.Arg(0), cpPending, cpConfirmed)
		if err != nil {
			return err
		}
		if err := restoreCheckpoint(m, "securemyserver undo"); err != nil {
			return err
		}
		out = fmt.Sprintf("Restored checkpoint %s (%s). %s", m.ID, strings.Join(m.Targets, ", "), m.StatusNote)
		return nil
	})
	if err != nil {
		fmt.Fprintln(stderr, "securemyserver undo:", err)
		return 1
	}
	fmt.Fprintln(stdout, strings.TrimSpace(out))
	return 0
}

func cmdAllow(name string, args []string, stdout, stderr io.Writer) int {
	if err := requireRoot(); err != nil {
		fmt.Fprintf(stderr, "securemyserver %s: %v\n", name, err)
		return 1
	}
	if name == "allowed" {
		list, err := allowedAll()
		if err != nil {
			fmt.Fprintln(stderr, "securemyserver allowed:", err)
			return 1
		}
		for _, s := range list {
			fmt.Fprintln(stdout, s)
		}
		if len(list) == 0 {
			fmt.Fprintln(stderr, "Nothing is allowed. Allow a switch with: sudo securemyserver allow <switch>")
			fmt.Fprintln(stderr, "You can allow:", allowNames())
		}
		return 0
	}
	if len(args) == 0 {
		fmt.Fprintf(stderr, "usage: sudo securemyserver %s <switch> [<switch>...] | --all-safe\nyou can allow: %s\n", name, allowNames())
		return 2
	}
	args = expandAllSafe(args)
	// All names are checked before anything changes, so a typo in the middle never leaves half of them allowed.
	for _, a := range args {
		if !knownAllow(a) {
			fmt.Fprintf(stderr, "securemyserver %s: unknown switch %q. Nothing was changed. You can allow: %s\n", name, a, allowNames())
			return 1
		}
	}
	seen := map[string]bool{}
	for _, a := range args {
		if seen[a] {
			continue
		}
		seen[a] = true
		if code := allowOne(name, a, stdout, stderr); code != 0 {
			return code
		}
	}
	return 0
}

// allSafeFlag stands for every safe switch this agent knows (D-090): "accept each of them when it is signed by my
// passkey". It names the switches only, never the blocklist or session-undo, which stay their own consent. A switch
// added in a later agent version needs its own allow (or --all-safe again).
const allSafeFlag = "--all-safe"

func expandAllSafe(args []string) []string {
	var out []string
	for _, a := range args {
		if a == allSafeFlag || a == "-all-safe" {
			out = append(out, switchNames...)
			continue
		}
		out = append(out, a)
	}
	return out
}

func allowOne(name, sw string, stdout, stderr io.Writer) int {
	var err error
	if name == "allow" {
		err = allowSwitch(sw)
	} else {
		err = disallowSwitch(sw)
	}
	if err != nil {
		fmt.Fprintf(stderr, "securemyserver %s: %v\n", name, err)
		return 1
	}
	if name == "disallow" && sw == blocklistAllow {
		if err := withLock(removeBlocklistTable); err != nil {
			fmt.Fprintf(stderr, "securemyserver disallow: removing the nft table inet %s failed: %v\n", nftTable, err)
			return 1
		}
	}
	switch {
	case name == "allow" && sw == blocklistAllow:
		fmt.Fprintln(stdout, "Allowed blocklist. After its next report the agent pulls the signed list into nftables (table inet securemyserver).")
	case name == "allow":
		fmt.Fprintf(stdout, "Allowed %s. It still needs your passkey tap in the dashboard to run.\n", sw)
	case sw == blocklistAllow:
		fmt.Fprintln(stdout, "Disallowed blocklist. The nft table inet securemyserver is removed.")
	default:
		fmt.Fprintf(stdout, "Disallowed %s. Signed requests for it are refused.\n", sw)
	}
	return 0
}
