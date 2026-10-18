//go:build linux

package installer

import (
	"fmt"
	"syscall"
)

// checkDisk verifies that the filesystem holding root has enough free
// space for the cache, the lists and the certificates.
func checkDisk(root string) Check {
	var st syscall.Statfs_t
	if err := syscall.Statfs(root, &st); err != nil {
		return Check{Name: "disk", Detail: fmt.Sprintf("не удалось проверить %s: %v", root, err)}
	}
	free := uint64(st.Bavail) * uint64(st.Bsize)
	if free < minFreeDisk {
		return Check{
			Name:   "disk",
			Detail: fmt.Sprintf("свободно %d MiB на %s, нужно не меньше %d MiB", free>>20, root, minFreeDisk>>20),
		}
	}
	return Check{Name: "disk", OK: true, Detail: fmt.Sprintf("свободно %d MiB на %s", free>>20, root)}
}
