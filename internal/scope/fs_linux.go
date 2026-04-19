//go:build linux

package scope

import "os"

func writeFileImpl(path, content string, mode uint32) error {
	return os.WriteFile(path, []byte(content), os.FileMode(mode))
}

func removeFileImpl(path string) error { return os.Remove(path) }
