package installer

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// checkByName returns the check with the given name, failing the test
// when Preflight did not report it at all.
func checkByName(t *testing.T, checks []Check, name string) Check {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			return c
		}
	}
	names := make([]string, 0, len(checks))
	for _, c := range checks {
		names = append(names, c.Name)
	}
	t.Fatalf("check %q not found in %v", name, names)
	return Check{}
}

// runnerFor returns a Runner that answers the given "name args..." keys
// and fails every unexpected command, so tests never touch the system.
func runnerFor(t *testing.T, responses map[string][]byte) func(string, ...string) ([]byte, error) {
	t.Helper()
	return func(name string, args ...string) ([]byte, error) {
		key := strings.Join(append([]string{name}, args...), " ")
		if out, ok := responses[key]; ok {
			return out, nil
		}
		return nil, fmt.Errorf("unexpected command %q", key)
	}
}

// TestParseOSRelease checks the key=value parsing of /etc/os-release,
// including quoted values and garbage input.
func TestParseOSRelease(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantID  string
		wantVer string
	}{
		{
			name: "ubuntu",
			data: "PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n" +
				"NAME=\"Ubuntu\"\n" +
				"VERSION_ID=\"24.04\"\n" +
				"VERSION_CODENAME=noble\n" +
				"ID=ubuntu\n",
			wantID:  "ubuntu",
			wantVer: "24.04",
		},
		{
			name: "debian",
			data: "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\n" +
				"ID=debian\n" +
				"VERSION_ID=\"13\"\n" +
				"VERSION_CODENAME=trixie\n",
			wantID:  "debian",
			wantVer: "13",
		},
		{
			name: "quoted values",
			data: "ID='debian'\n" +
				"VERSION_ID = \"13\" \n" +
				"# a comment\n" +
				"\n" +
				"URL=\"https://debian.org\"\n",
			wantID:  "debian",
			wantVer: "13",
		},
		{
			name:    "codename without version",
			data:    "ID=debian\nVERSION_CODENAME=trixie\n",
			wantID:  "debian",
			wantVer: "trixie",
		},
		{
			name:    "garbage",
			data:    "this is not an os-release file\nломаный мусор\n",
			wantID:  "",
			wantVer: "",
		},
		{
			name:    "empty",
			data:    "",
			wantID:  "",
			wantVer: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, version := parseOSRelease([]byte(tt.data))
			if id != tt.wantID || version != tt.wantVer {
				t.Errorf("parseOSRelease(%q) = (%q, %q), want (%q, %q)",
					tt.data, id, version, tt.wantID, tt.wantVer)
			}
		})
	}
}

// TestSupportedDistro pins the supported distributions: Ubuntu 24.04 and
// Debian 13 (trixie); older releases and unknown IDs are rejected.
func TestSupportedDistro(t *testing.T) {
	tests := []struct {
		id      string
		version string
		want    bool
	}{
		{"ubuntu", "24.04", true},
		{"ubuntu", "24.04.1", false},
		{"ubuntu", "noble", true},
		{"ubuntu", "22.04", false},
		{"debian", "13", true},
		{"debian", "trixie", true},
		{"debian", "12", false},
		{"debian", "bookworm", false},
		{"centos", "9", false},
		{"", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.id+" "+tt.version, func(t *testing.T) {
			if got := supportedDistro(tt.id, tt.version); got != tt.want {
				t.Errorf("supportedDistro(%q, %q) = %v, want %v", tt.id, tt.version, got, tt.want)
			}
		})
	}
}

// freePort learns a currently free wildcard port and releases it again.
func freePort(t *testing.T, network string) int {
	t.Helper()
	switch network {
	case "tcp":
		l, err := net.Listen("tcp", "0.0.0.0:0")
		if err != nil {
			t.Fatalf("learn free tcp port: %v", err)
		}
		port := l.Addr().(*net.TCPAddr).Port
		l.Close()
		return port
	case "udp":
		c, err := net.ListenPacket("udp", "0.0.0.0:0")
		if err != nil {
			t.Fatalf("learn free udp port: %v", err)
		}
		port := c.LocalAddr().(*net.UDPAddr).Port
		c.Close()
		return port
	default:
		t.Fatalf("unknown network %q", network)
		return 0
	}
}

// occupyPort binds a wildcard port of the given network and keeps it busy
// until the test ends.
func occupyPort(t *testing.T, network string) int {
	t.Helper()
	switch network {
	case "tcp":
		l, err := net.Listen("tcp", "0.0.0.0:0")
		if err != nil {
			t.Fatalf("occupy tcp port: %v", err)
		}
		t.Cleanup(func() { l.Close() })
		return l.Addr().(*net.TCPAddr).Port
	case "udp":
		c, err := net.ListenPacket("udp", "0.0.0.0:0")
		if err != nil {
			t.Fatalf("occupy udp port: %v", err)
		}
		t.Cleanup(func() { c.Close() })
		return c.LocalAddr().(*net.UDPAddr).Port
	default:
		t.Fatalf("unknown network %q", network)
		return 0
	}
}

// TestPortChecks binds high ports to learn their numbers: free ones pass
// the check, an occupied TCP port and an occupied UDP port are reported.
func TestPortChecks(t *testing.T) {
	failingRunner := func(string, ...string) ([]byte, error) {
		return nil, errors.New("command not found")
	}

	t.Run("free ports", func(t *testing.T) {
		p1 := freePort(t, "tcp")
		p2 := freePort(t, "udp")
		checks := Preflight(Options{Root: t.TempDir(), BindPorts: []int{p1, p2}, Runner: failingRunner})
		chk := checkByName(t, checks, "ports")
		if !chk.OK {
			t.Fatalf("ports check = %+v, want OK for free ports %d, %d", chk, p1, p2)
		}
	})

	t.Run("busy ports", func(t *testing.T) {
		tcpBusy := occupyPort(t, "tcp")
		udpBusy := occupyPort(t, "udp")
		checks := Preflight(Options{
			Root:      t.TempDir(),
			BindPorts: []int{tcpBusy, udpBusy},
			Runner:    failingRunner,
		})
		chk := checkByName(t, checks, "ports")
		if chk.OK {
			t.Fatalf("ports check = %+v, want failure for busy ports %d, %d", chk, tcpBusy, udpBusy)
		}
		for _, port := range []int{tcpBusy, udpBusy} {
			if !strings.Contains(chk.Detail, strconv.Itoa(port)) {
				t.Errorf("ports detail %q does not mention busy port %d", chk.Detail, port)
			}
		}
	})

	t.Run("busy ports with ss holder", func(t *testing.T) {
		tcpBusy := occupyPort(t, "tcp")
		ssOut := fmt.Sprintf("Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"+
			"tcp   LISTEN 0      4096       0.0.0.0:%d      0.0.0.0:*         users:((\"other-dns\",pid=4242,fd=4))\n",
			tcpBusy)
		runner := runnerFor(t, map[string][]byte{"ss -ltnup": []byte(ssOut)})
		checks := Preflight(Options{Root: t.TempDir(), BindPorts: []int{tcpBusy}, Runner: runner})
		chk := checkByName(t, checks, "ports")
		if chk.OK {
			t.Fatalf("ports check = %+v, want failure for busy port %d", chk, tcpBusy)
		}
		if !strings.Contains(chk.Detail, "other-dns") {
			t.Errorf("ports detail %q does not name the holder from ss", chk.Detail)
		}
	})

	t.Run("no ports", func(t *testing.T) {
		checks := Preflight(Options{Root: t.TempDir(), Runner: failingRunner})
		chk := checkByName(t, checks, "ports")
		if !chk.OK {
			t.Fatalf("ports check = %+v, want OK without ports", chk)
		}
	})
}

// TestOurServicePortsAreNotBlocking checks that a re-run over a running
// mdns service is not aborted by its own ports, while ports held by
// anything else still fail. The holder comes from the ss output, so the
// test fakes ss and occupies real ports to make them look busy.
func TestOurServicePortsAreNotBlocking(t *testing.T) {
	mdnsPort := occupyPort(t, "tcp")
	nginxPort := occupyPort(t, "tcp")
	lookalikePort := occupyPort(t, "tcp")

	ss := func(port int, name string) string {
		return fmt.Sprintf("tcp   LISTEN 0      4096       0.0.0.0:%d      0.0.0.0:*         users:((\"%s\",pid=4242,fd=4))\n", port, name)
	}
	ssOut := "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n" +
		ss(mdnsPort, "mdns") +
		ss(nginxPort, "nginx") +
		ss(lookalikePort, "mdns-helper")
	runner := runnerFor(t, map[string][]byte{"ss -ltnup": []byte(ssOut)})

	t.Run("our own mdns is fine", func(t *testing.T) {
		chk := checkByName(t, Preflight(Options{Root: t.TempDir(), BindPorts: []int{mdnsPort}, Runner: runner}), "ports")
		if !chk.OK {
			t.Fatalf("ports check = %+v, want OK for our own mdns on %d", chk, mdnsPort)
		}
		want := fmt.Sprintf("%d занят текущим mdns (ок, перезапустится)", mdnsPort)
		if !strings.Contains(chk.Detail, want) {
			t.Errorf("ports detail %q does not contain %q", chk.Detail, want)
		}
	})

	t.Run("a foreign holder still fails", func(t *testing.T) {
		chk := checkByName(t, Preflight(Options{Root: t.TempDir(), BindPorts: []int{nginxPort}, Runner: runner}), "ports")
		if chk.OK {
			t.Fatalf("ports check = %+v, want failure for nginx on %d", chk, nginxPort)
		}
		if !strings.Contains(chk.Detail, "nginx") {
			t.Errorf("ports detail %q does not name nginx", chk.Detail)
		}
	})

	t.Run("a name that merely contains mdns still fails", func(t *testing.T) {
		chk := checkByName(t, Preflight(Options{Root: t.TempDir(), BindPorts: []int{lookalikePort}, Runner: runner}), "ports")
		if chk.OK {
			t.Fatalf("ports check = %+v, want failure for mdns-helper on %d", chk, lookalikePort)
		}
		if !strings.Contains(chk.Detail, "mdns-helper") {
			t.Errorf("ports detail %q does not name mdns-helper", chk.Detail)
		}
	})

	t.Run("no holder info still fails", func(t *testing.T) {
		failingRunner := func(string, ...string) ([]byte, error) {
			return nil, errors.New("ss: not found")
		}
		chk := checkByName(t, Preflight(Options{Root: t.TempDir(), BindPorts: []int{mdnsPort}, Runner: failingRunner}), "ports")
		if chk.OK {
			t.Errorf("ports check = %+v, want failure when the holder is unknown", chk)
		}
	})

	t.Run("mixed own and foreign fails on the foreign one, noting ours", func(t *testing.T) {
		chk := checkByName(t, Preflight(Options{Root: t.TempDir(), BindPorts: []int{mdnsPort, nginxPort}, Runner: runner}), "ports")
		if chk.OK {
			t.Fatalf("ports check = %+v, want failure with nginx holding %d", chk, nginxPort)
		}
		if !strings.Contains(chk.Detail, "nginx") {
			t.Errorf("ports detail %q does not name nginx", chk.Detail)
		}
		if !strings.Contains(chk.Detail, "занят текущим mdns") {
			t.Errorf("ports detail %q does not note the mdns-held port", chk.Detail)
		}
	})
}

// TestResolvedWarning checks that a local systemd-resolved stub listener
// is reported as a warning with the DNSStubListener=no instruction.
func TestResolvedWarning(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "run", "systemd", "resolve", "stub-resolv.conf")
	if err := os.MkdirAll(filepath.Dir(marker), 0o755); err != nil {
		t.Fatalf("create resolved marker dir: %v", err)
	}
	if err := os.WriteFile(marker, []byte("nameserver 127.0.0.53\n"), 0o644); err != nil {
		t.Fatalf("write resolved marker: %v", err)
	}

	runner := runnerFor(t, map[string][]byte{
		"systemctl --version":                  []byte("systemd 255 (255.4-1ubuntu8)\n"),
		"systemctl is-active systemd-resolved": []byte("active\n"),
	})

	checks := Preflight(Options{Root: root, Runner: runner})
	chk := checkByName(t, checks, "systemd-resolved")
	if chk.OK {
		t.Errorf("systemd-resolved check = %+v, want not OK with resolved active", chk)
	}
	if !chk.Warning {
		t.Errorf("systemd-resolved check Warning = false, want true")
	}
	if !strings.Contains(chk.Detail, "DNSStubListener=no") {
		t.Errorf("systemd-resolved detail %q does not contain the DNSStubListener=no instruction", chk.Detail)
	}

	t.Run("inactive is fine", func(t *testing.T) {
		runner := runnerFor(t, map[string][]byte{
			"systemctl --version":                  []byte("systemd 255\n"),
			"systemctl is-active systemd-resolved": []byte("inactive\n"),
		})
		chk := checkByName(t, Preflight(Options{Root: root, Runner: runner}), "systemd-resolved")
		if !chk.OK || chk.Warning {
			t.Errorf("systemd-resolved check = %+v, want OK without warning for inactive service", chk)
		}
	})

	t.Run("no marker", func(t *testing.T) {
		chk := checkByName(t, Preflight(Options{Root: t.TempDir(), Runner: runner}), "systemd-resolved")
		if !chk.OK || chk.Warning {
			t.Errorf("systemd-resolved check = %+v, want OK without warning without the marker", chk)
		}
	})
}

// TestSystemdMissingFails checks that the systemd check needs both the
// runtime directory and a working systemctl.
func TestSystemdMissingFails(t *testing.T) {
	t.Run("missing runtime dir", func(t *testing.T) {
		checks := Preflight(Options{Root: t.TempDir()})
		chk := checkByName(t, checks, "systemd")
		if chk.OK {
			t.Errorf("systemd check = %+v, want not OK without /run/systemd/system", chk)
		}
	})

	t.Run("systemctl fails", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "run", "systemd", "system"), 0o755); err != nil {
			t.Fatalf("create systemd dir: %v", err)
		}
		runner := func(string, ...string) ([]byte, error) {
			return nil, errors.New("exec: systemctl: not found")
		}
		chk := checkByName(t, Preflight(Options{Root: root, Runner: runner}), "systemd")
		if chk.OK {
			t.Errorf("systemd check = %+v, want not OK when systemctl fails", chk)
		}
	})

	t.Run("present", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "run", "systemd", "system"), 0o755); err != nil {
			t.Fatalf("create systemd dir: %v", err)
		}
		runner := runnerFor(t, map[string][]byte{
			"systemctl --version": []byte("systemd 255\n"),
		})
		chk := checkByName(t, Preflight(Options{Root: root, Runner: runner}), "systemd")
		if !chk.OK {
			t.Errorf("systemd check = %+v, want OK with the runtime dir and systemctl", chk)
		}
	})
}

// TestARecordNameMismatchWarns compares the public A/AAAA records of the
// domain with the local addresses through the test seams.
func TestARecordNameMismatchWarns(t *testing.T) {
	tests := []struct {
		name        string
		domain      string
		resolved    []string
		resolveErr  error
		local       []string
		wantOK      bool
		wantWarning bool
		wantDetail  []string
	}{
		{
			name:     "match ipv4",
			domain:   "dns.example.com",
			resolved: []string{"203.0.113.7"},
			local:    []string{"127.0.0.1", "203.0.113.7"},
			wantOK:   true,
		},
		{
			name:     "match ipv6",
			domain:   "dns.example.com",
			resolved: []string{"2001:db8::1"},
			local:    []string{"2001:db8::1"},
			wantOK:   true,
		},
		{
			name:        "mismatch",
			domain:      "dns.example.com",
			resolved:    []string{"198.51.100.9", "2001:db8::2"},
			local:       []string{"203.0.113.7"},
			wantOK:      false,
			wantWarning: true,
			wantDetail:  []string{"198.51.100.9", "203.0.113.7"},
		},
		{
			name:        "resolve error",
			domain:      "dns.example.com",
			resolveErr:  errors.New("lookup dns.example.com: no such host"),
			local:       []string{"203.0.113.7"},
			wantOK:      false,
			wantWarning: true,
			wantDetail:  []string{"не удалось разрешить", "no such host"},
		},
		{
			name:       "no domain",
			domain:     "",
			resolved:   []string{"203.0.113.7"},
			local:      []string{"203.0.113.7"},
			wantOK:     true,
			wantDetail: []string{"домен не задан"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolveCalls := 0
			checks := Preflight(Options{
				Root:   t.TempDir(),
				Domain: tt.domain,
				Runner: func(string, ...string) ([]byte, error) { return nil, errors.New("no commands") },
				ResolveFn: func(string) ([]string, error) {
					resolveCalls++
					return tt.resolved, tt.resolveErr
				},
				LocalAddrsFn: func() []string { return tt.local },
			})
			chk := checkByName(t, checks, "dns-a-record")
			if chk.OK != tt.wantOK {
				t.Errorf("dns-a-record check = %+v, want OK %v", chk, tt.wantOK)
			}
			if chk.Warning != tt.wantWarning {
				t.Errorf("dns-a-record check = %+v, want Warning %v", chk, tt.wantWarning)
			}
			for _, want := range tt.wantDetail {
				if !strings.Contains(chk.Detail, want) {
					t.Errorf("dns-a-record detail %q does not contain %q", chk.Detail, want)
				}
			}
			if tt.domain == "" && resolveCalls != 0 {
				t.Errorf("ResolveFn called %d times without a domain, want 0", resolveCalls)
			}
		})
	}
}

// TestPreflightReturnsAllChecks pins the check names and their order:
// Preflight never stops early.
func TestPreflightReturnsAllChecks(t *testing.T) {
	want := []string{
		"root", "os-release", "arch", "systemd",
		"ports", "systemd-resolved", "dns-a-record", "disk",
	}

	checks := Preflight(Options{Root: t.TempDir()})
	got := make([]string, 0, len(checks))
	for _, c := range checks {
		got = append(got, c.Name)
	}
	if len(got) != len(want) {
		t.Fatalf("Preflight returned %d checks (%v), want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("check %d = %q, want %q", i, got[i], want[i])
		}
	}
	for _, c := range checks {
		if c.Detail == "" {
			t.Errorf("check %q has an empty Detail", c.Name)
		}
	}
}
