package main

import (
	"bytes"
	"os"
	"path"
	"strconv"
	"strings"
)

// A listening program is named from this fixed list, so the dashboard can flag exposed databases and
// development or AI tools (docs: daemon/README.md "Exposed databases and dev tools"). The process name and command
// line are read here, on the server, only to pick a name from the list: the command line itself is never sent
// (D-017). Keep the ids in sync with src/lib/report/exposure.ts.
type toolRule struct {
	id    string
	comms []string // exact /proc/<pid>/comm values (15 characters at most)
	match func(comm string, args []string) bool
}

var toolRules = []toolRule{
	{id: "postgres", comms: []string{"postgres", "postmaster"}},
	{id: "mysql", comms: []string{"mysqld", "mariadbd"}},
	{id: "redis", comms: []string{"redis-server"}},
	{id: "mongodb", comms: []string{"mongod"}},
	{id: "elasticsearch", match: func(_ string, a []string) bool {
		return anyArg(a, func(s string) bool { return strings.HasPrefix(s, "org.elasticsearch.bootstrap.") })
	}},
	{id: "memcached", comms: []string{"memcached"}},
	{id: "clickhouse", comms: []string{"clickhouse-serv", "clickhouse"}},
	{id: "jupyter", match: func(c string, a []string) bool {
		return strings.HasPrefix(c, "jupyter") || anyArg(a, func(s string) bool { return strings.HasPrefix(path.Base(s), "jupyter-") }) ||
			argPair(a, "jupyter", "lab", "notebook", "server")
	}},
	{id: "code-server", match: func(_ string, a []string) bool {
		return anyArg(a, func(s string) bool { return path.Base(s) == "code-server" || strings.Contains(s, "/code-server/") })
	}},
	{id: "vite", match: func(_ string, a []string) bool {
		return anyArg(a, func(s string) bool { return path.Base(s) == "vite" || strings.HasSuffix(s, "/vite/bin/vite.js") })
	}},
	{id: "ollama", comms: []string{"ollama"}},
	{id: "open-webui", match: func(_ string, a []string) bool {
		return anyArg(a, func(s string) bool { return path.Base(s) == "open-webui" || strings.HasPrefix(s, "open_webui.main") })
	}},
	{id: "comfyui", match: func(_ string, a []string) bool {
		return anyArg(a, func(s string) bool { return strings.HasSuffix(strings.ToLower(s), "comfyui/main.py") })
	}},
	{id: "openclaw", match: func(c string, a []string) bool {
		if strings.HasPrefix(c, "openclaw") {
			return true
		}
		return anyArg(a, func(s string) bool {
			b := path.Base(s)
			return b == "openclaw" || b == "openclaw.mjs" || b == "clawdbot" || b == "moltbot"
		})
	}},
}

// classifyTool names a listening program from toolRules, or "". `next dev` is recognized from the parent of the
// listening process: the server runs in a child titled "next-server (vX)" for both `next dev` and `next start`.
func classifyTool(comm string, args, parentArgs []string) string {
	for _, r := range toolRules {
		for _, c := range r.comms {
			if comm == c {
				return r.id
			}
		}
		if r.match != nil && r.match(comm, args) {
			return r.id
		}
	}
	if isNextDev(args) || (strings.HasPrefix(comm, "next-server") && isNextDev(parentArgs)) {
		return "next-dev"
	}
	return ""
}

func isNextDev(a []string) bool {
	for i, s := range a {
		b := path.Base(s)
		if (b == "next" || strings.HasSuffix(s, "/next/dist/bin/next")) && i+1 < len(a) && a[i+1] == "dev" {
			return true
		}
	}
	return false
}

func anyArg(a []string, f func(string) bool) bool {
	for _, s := range a {
		if f(s) {
			return true
		}
	}
	return false
}

// argPair: an argument whose base name is `first`, followed by one of `next`.
func argPair(a []string, first string, next ...string) bool {
	for i := 0; i+1 < len(a); i++ {
		if path.Base(a[i]) != first {
			continue
		}
		for _, n := range next {
			if a[i+1] == n {
				return true
			}
		}
	}
	return false
}

// procArgs reads /proc/<pid>/cmdline (at most 4 KiB, 32 arguments). Used only by classifyTool, never sent.
func procArgs(pid int) []string {
	if pid <= 0 {
		return nil
	}
	b, err := readCapped("/proc/"+strconv.Itoa(pid)+"/cmdline", 4096)
	if err != nil {
		return nil
	}
	parts := bytes.Split(bytes.TrimRight(b, "\x00"), []byte{0})
	out := make([]string, 0, min(len(parts), 32))
	for _, p := range parts {
		if len(out) == 32 {
			break
		}
		out = append(out, string(p))
	}
	return out
}

// parentPID reads the ppid from /proc/<pid>/stat (field 4, after the parenthesized name).
func parentPID(pid int) int {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 2 {
		return 0
	}
	n, _ := strconv.Atoi(f[1])
	return n
}

// toolOf names the program behind a listening socket, reading its command line (and its parent's) locally.
func toolOf(pid int, comm string) string {
	if pid <= 0 {
		return ""
	}
	var parent []string
	if strings.HasPrefix(comm, "next-server") {
		parent = procArgs(parentPID(pid))
	}
	return classifyTool(comm, procArgs(pid), parent)
}
