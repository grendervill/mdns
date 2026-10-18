//go:build !linux

package installer

// checkDisk is a no-op outside Linux: the free-space check uses the
// statfs syscall, which is only wired up in disk_linux.go. Development
// happens on macOS, where the check is reported as skipped.
func checkDisk(_ string) Check {
	return Check{Name: "disk", OK: true, Detail: "пропущено: проверка свободного места поддерживается только на Linux"}
}
