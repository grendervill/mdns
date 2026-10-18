// Package installer performs the system-level installation of the mdns
// server: preflight checks, files, the systemd unit and the
// non-interactive setup. Every file and system operation is rooted in
// Options.Root and every command goes through Options.Runner, so the
// package is testable without root and without touching the real
// system.
package installer

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Installation paths. The installer writes the binary to BinaryPath, the
// systemd unit to UnitPath and the config to DefaultConfigPath; all of
// them live under the real root, not under Options.Root (which only
// makes the preflight checks testable).
const (
	// BinaryPath is where the mdns binary is installed.
	BinaryPath = "/usr/local/bin/mdns"
	// UnitPath is the installed systemd unit of the service.
	UnitPath = "/etc/systemd/system/mdns.service"
	// DefaultConfigPath is the default configuration file.
	DefaultConfigPath = "/etc/mdns/config.json"
	// DefaultDataDir is the default data directory (cache, lists,
	// certificates).
	DefaultDataDir = "/var/lib/mdns"

	// resolvedDropIn is where the instruction disables the
	// systemd-resolved stub listener.
	resolvedDropIn = "etc/systemd/resolved.conf.d/99-mdns.conf"
	// minFreeDisk is the minimum free space on the installation mount.
	minFreeDisk = 500 << 20
	// resolveServer is the public resolver used for the A/AAAA check.
	resolveServer = "1.1.1.1:53"
	// commandTimeout bounds the auxiliary commands and DNS lookups.
	commandTimeout = 5 * time.Second
)

// Check is the result of one preflight check. Warning marks a problem
// that does not block the installation: the caller decides whether it
// still proceeds.
type Check struct {
	Name    string
	OK      bool
	Warning bool
	Detail  string
}

// Options configures the preflight checks. Root is the prefix for every
// system marker (/etc/os-release, /run/systemd/system, the disk mount
// root); tests pass a temporary directory. ConfigPath and DataDir fall
// back to their defaults under Root when empty.
type Options struct {
	Root       string // default "/"; tests use t.TempDir()
	ConfigPath string // default <Root>/etc/mdns/config.json
	DataDir    string // default <Root>/var/lib/mdns
	BindPorts  []int  // 53, 80, 443, 853 (from the selected protocols)
	Domain     string
	Runner     func(name string, args ...string) ([]byte, error) // systemctl etc.; nil → exec

	// ResolveFn resolves the public A/AAAA records of a domain; nil
	// uses 1.1.1.1. LocalAddrsFn returns the global unicast addresses
	// of the local interfaces; nil uses net.InterfaceAddrs. Tests
	// inject both to compare addresses without network access.
	ResolveFn    func(domain string) ([]string, error)
	LocalAddrsFn func() []string
}

// withDefaults fills the zero values of Options.
func (o Options) withDefaults() Options {
	if o.Root == "" {
		o.Root = "/"
	}
	if o.ConfigPath == "" {
		o.ConfigPath = filepath.Join(o.Root, "etc/mdns/config.json")
	}
	if o.DataDir == "" {
		o.DataDir = filepath.Join(o.Root, "var/lib/mdns")
	}
	if o.Runner == nil {
		o.Runner = execRunner
	}
	if o.ResolveFn == nil {
		o.ResolveFn = resolvePublic
	}
	if o.LocalAddrsFn == nil {
		o.LocalAddrsFn = localAddrs
	}
	return o
}

// execRunner is the default Runner: it runs the command and returns its
// combined output.
func execRunner(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// Preflight runs every check and returns all of them, in a fixed order;
// it never stops early, so the caller can show the full picture and
// decide what blocks the installation.
func Preflight(opts Options) []Check {
	opts = opts.withDefaults()
	return []Check{
		checkRoot(),
		checkOSRelease(opts),
		checkArch(),
		checkSystemd(opts),
		checkPorts(opts),
		checkSystemdResolved(opts),
		checkARecord(opts),
		checkDisk(opts.Root),
	}
}

// checkRoot verifies that the installer runs as root.
func checkRoot() Check {
	if os.Geteuid() == 0 {
		return Check{Name: "root", OK: true, Detail: "запуск от root"}
	}
	return Check{
		Name:   "root",
		Detail: fmt.Sprintf("нужны права root, текущий euid %d; запустите установку через sudo", os.Geteuid()),
	}
}

// checkOSRelease verifies that the distribution is supported.
func checkOSRelease(opts Options) Check {
	path := filepath.Join(opts.Root, "etc/os-release")
	data, err := os.ReadFile(path)
	if err != nil {
		return Check{Name: "os-release", Detail: fmt.Sprintf("не удалось прочитать %s: %v", path, err)}
	}
	id, version := parseOSRelease(data)
	if supportedDistro(id, version) {
		return Check{Name: "os-release", OK: true, Detail: fmt.Sprintf("%s %s", id, version)}
	}
	if id == "" {
		return Check{Name: "os-release", Detail: fmt.Sprintf("%s не содержит ID дистрибутива", path)}
	}
	return Check{
		Name:   "os-release",
		Detail: fmt.Sprintf("%s %s не поддерживается, нужны Ubuntu 24.04 или Debian 13", id, version),
	}
}

// parseOSRelease parses the key=value lines of an os-release file,
// unquoting the values, and returns the distribution ID and its version.
// When the file has no VERSION_ID the version codename is returned
// instead, so that both "debian 13" and "debian trixie" are recognised.
// Garbage input yields empty strings.
func parseOSRelease(data []byte) (id, versionID string) {
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)
		values[key] = value
	}
	id = values["ID"]
	versionID = values["VERSION_ID"]
	if versionID == "" {
		versionID = values["VERSION_CODENAME"]
	}
	return id, versionID
}

// supportedDistro reports whether the installer supports the
// distribution: Ubuntu 24.04 (noble) and Debian 13 (trixie), given either
// by version or by codename.
func supportedDistro(id, versionID string) bool {
	v := strings.ToLower(strings.TrimSpace(versionID))
	switch strings.ToLower(strings.TrimSpace(id)) {
	case "ubuntu":
		return v == "24.04" || v == "noble"
	case "debian":
		return v == "13" || v == "trixie"
	}
	return false
}

// checkArch verifies that the binary matches a supported architecture.
func checkArch() Check {
	switch runtime.GOARCH {
	case "amd64", "arm64":
		return Check{Name: "arch", OK: true, Detail: runtime.GOARCH}
	}
	return Check{Name: "arch", Detail: fmt.Sprintf("архитектура %s не поддерживается, нужны amd64 или arm64", runtime.GOARCH)}
}

// checkSystemd verifies that the system runs systemd.
func checkSystemd(opts Options) Check {
	dir := filepath.Join(opts.Root, "run/systemd/system")
	if _, err := os.Stat(dir); err != nil {
		return Check{Name: "systemd", Detail: fmt.Sprintf("нет %s: система не использует systemd", dir)}
	}
	out, err := opts.Runner("systemctl", "--version")
	if err != nil {
		return Check{Name: "systemd", Detail: fmt.Sprintf("systemctl --version: %v", err)}
	}
	version, _, _ := strings.Cut(strings.TrimSpace(string(out)), "\n")
	return Check{Name: "systemd", OK: true, Detail: version}
}

// checkPorts verifies that every port the server needs is free, for TCP
// and UDP alike.
func checkPorts(opts Options) Check {
	var busy []int
	for _, port := range opts.BindPorts {
		if port <= 0 {
			continue
		}
		if portBusy(port) {
			busy = append(busy, port)
		}
	}
	if len(busy) == 0 {
		return Check{Name: "ports", OK: true, Detail: fmt.Sprintf("порты свободны: %s", portList(opts.BindPorts))}
	}
	holders := ssHolders(opts)
	parts := make([]string, 0, len(busy))
	for _, port := range busy {
		if h := holders[port]; h != "" {
			parts = append(parts, fmt.Sprintf("%d (занят: %s)", port, h))
			continue
		}
		parts = append(parts, fmt.Sprintf("%d (занят)", port))
	}
	return Check{
		Name:   "ports",
		Detail: fmt.Sprintf("заняты порты: %s; остановите держащие их службы", strings.Join(parts, ", ")),
	}
}

// portBusy reports whether 0.0.0.0:port cannot be bound on TCP or UDP.
func portBusy(port int) bool {
	addr := net.JoinHostPort("0.0.0.0", strconv.Itoa(port))
	if l, err := net.Listen("tcp", addr); err == nil {
		l.Close()
	} else {
		return true
	}
	if c, err := net.ListenPacket("udp", addr); err == nil {
		c.Close()
	} else {
		return true
	}
	return false
}

// portList renders a port list for the human-readable detail.
func portList(ports []int) string {
	if len(ports) == 0 {
		return "(нет)"
	}
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, strconv.Itoa(p))
	}
	return strings.Join(parts, ", ")
}

// ssHolders maps busy ports to their holder process, best effort: when ss
// is unavailable or its output does not mention the port, the port has no
// holder name.
func ssHolders(opts Options) map[int]string {
	holders := map[int]string{}
	out, err := opts.Runner("ss", "-ltnup")
	if err != nil {
		return holders
	}
	for _, line := range strings.Split(string(out), "\n") {
		name := ssProcess(line)
		port := ssLocalPort(line)
		if name == "" || port <= 0 {
			continue
		}
		for _, want := range opts.BindPorts {
			if want == port {
				holders[port] = name
			}
		}
	}
	return holders
}

// ssLocalPort extracts the local port from the address columns of an ss
// -ltnup line: the first address:port field with a numeric port. It
// returns 0 for a header line or unrecognised input.
func ssLocalPort(line string) int {
	fields := strings.Fields(line)
	for i := 2; i < len(fields); i++ {
		field := fields[i]
		if strings.HasPrefix(field, "users:(") {
			break
		}
		j := strings.LastIndexByte(field, ':')
		if j < 0 {
			continue
		}
		port, err := strconv.Atoi(field[j+1:])
		if err != nil {
			continue
		}
		return port
	}
	return 0
}

// ssProcess extracts the process name from the users:(("name",pid=...))
// column of ss output.
func ssProcess(line string) string {
	const marker = `users:(("`
	i := strings.Index(line, marker)
	if i < 0 {
		return ""
	}
	rest := line[i+len(marker):]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// checkSystemdResolved warns when the local systemd-resolved stub
// listener occupies :53: the server would not be able to bind it.
func checkSystemdResolved(opts Options) Check {
	const name = "systemd-resolved"
	marker := filepath.Join(opts.Root, "run/systemd/resolve/stub-resolv.conf")
	if _, err := os.Stat(marker); err != nil {
		return Check{Name: name, OK: true, Detail: "systemd-resolved не обнаружен"}
	}
	out, err := opts.Runner("systemctl", "is-active", "systemd-resolved")
	if err != nil {
		return Check{Name: name, OK: true, Detail: fmt.Sprintf("%s есть, но systemctl is-active: %v", marker, err)}
	}
	if !hasActiveState(string(out)) {
		return Check{Name: name, OK: true, Detail: fmt.Sprintf("%s есть, служба systemd-resolved не активна", marker)}
	}
	dropIn := filepath.Join(opts.Root, resolvedDropIn)
	return Check{
		Name:    name,
		Warning: true,
		Detail: fmt.Sprintf("systemd-resolved слушает :53 и займёт порт DNS; отключите его заглушку:\n"+
			"  printf \"[Resolve]\\nDNSStubListener=no\\n\" | sudo tee %s\n"+
			"  sudo systemctl restart systemd-resolved", dropIn),
	}
}

// hasActiveState reports whether systemctl is-active output holds the
// "active" (or "activating") state word, and not merely its "inactive"
// substring.
func hasActiveState(out string) bool {
	for _, field := range strings.Fields(out) {
		if field == "active" || field == "activating" {
			return true
		}
	}
	return false
}

// checkARecord compares the public A/AAAA records of the domain with the
// global unicast addresses of the local interfaces. A mismatch means the
// certificate cannot be issued until the DNS record points here.
func checkARecord(opts Options) Check {
	const name = "dns-a-record"
	if opts.Domain == "" {
		return Check{Name: name, OK: true, Detail: "домен не задан"}
	}
	resolved, err := opts.ResolveFn(opts.Domain)
	if err != nil {
		return Check{
			Name:    name,
			Warning: true,
			Detail:  fmt.Sprintf("не удалось разрешить A/AAAA %s: %v", opts.Domain, err),
		}
	}
	local := opts.LocalAddrsFn()
	if matchesAny(resolved, local) {
		return Check{
			Name:   name,
			OK:     true,
			Detail: fmt.Sprintf("%s → %s, совпадает с локальным адресом", opts.Domain, addrList(resolved)),
		}
	}
	return Check{
		Name:    name,
		Warning: true,
		Detail: fmt.Sprintf("A/AAAA %s → %s, локальные адреса: %s; запись домена должна указывать на этот сервер",
			opts.Domain, addrList(resolved), addrList(local)),
	}
}

// matchesAny reports whether the two address lists share a normalised
// address.
func matchesAny(a, b []string) bool {
	set := make(map[string]bool, len(b))
	for _, addr := range b {
		set[normalAddr(addr)] = true
	}
	for _, addr := range a {
		if set[normalAddr(addr)] {
			return true
		}
	}
	return false
}

// normalAddr normalises an address so that equal IPs compare equal.
func normalAddr(addr string) string {
	if ip := net.ParseIP(strings.TrimSpace(addr)); ip != nil {
		return ip.String()
	}
	return strings.TrimSpace(addr)
}

// addrList renders an address list for the human-readable detail.
func addrList(addrs []string) string {
	if len(addrs) == 0 {
		return "(нет)"
	}
	return strings.Join(addrs, ", ")
}

// resolvePublic resolves the A and AAAA records of domain through the
// public resolver. An empty record set is not an error.
func resolvePublic(domain string) ([]string, error) {
	c := &dns.Client{Net: "udp", Timeout: commandTimeout}
	var (
		addrs    []string
		firstErr error
	)
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), qtype)
		resp, _, err := c.Exchange(m, resolveServer)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, rr := range resp.Answer {
			switch v := rr.(type) {
			case *dns.A:
				addrs = append(addrs, v.A.String())
			case *dns.AAAA:
				addrs = append(addrs, v.AAAA.String())
			}
		}
	}
	if len(addrs) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return addrs, nil
}

// localAddrs returns the global unicast addresses of the local
// interfaces, the ones a public A/AAAA record may point to.
func localAddrs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var addrs []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		ifaceAddrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range ifaceAddrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP
			if !ip.IsGlobalUnicast() || ip.IsLoopback() {
				continue
			}
			addrs = append(addrs, ip.String())
		}
	}
	return addrs
}
