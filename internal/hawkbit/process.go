package hawkbit

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	runtimeDir    = "/run/naos/core"
	updaterBinary = "/usr/bin/rauc-hawkbit-updater"
	logLimit      = 64 * 1024
)

// ProcessIdentity is attached to the current update task for mutual exclusion.
// It is not used to adopt an old updater after Core restarts.
type ProcessIdentity struct {
	PID          int    `json:"pid"`
	StartTime    uint64 `json:"start_time"`
	BootID       string `json:"boot_id"`
	Exe          string `json:"exe"`
	ConfigPath   string `json:"config_path"`
	ConfigSHA256 string `json:"config_sha256"`
}

func configPath(directory string) string { return filepath.Join(directory, "hawkbit.conf") }
func logPath(directory string) string    { return filepath.Join(directory, "hawkbit-updater.log") }

func readPrivate(path string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > limit {
		return nil, errors.New("invalid private hawkBit file")
	}
	if s, ok := info.Sys().(*syscall.Stat_t); !ok || s.Nlink != 1 || s.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("invalid hawkBit file ownership")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("private hawkBit file exceeds limit")
	}
	return data, nil
}

func processIdentity(pid int) (ProcessIdentity, error) {
	if pid < 1 {
		return ProcessIdentity{}, errors.New("invalid process identifier")
	}
	prefix := "/proc/" + strconv.Itoa(pid)
	data, err := os.ReadFile(prefix + "/stat")
	if err != nil {
		return ProcessIdentity{}, err
	}
	end := bytes.LastIndex(data, []byte(") "))
	if end < 0 {
		return ProcessIdentity{}, errors.New("invalid Linux process stat")
	}
	fields := strings.Fields(string(data[end+2:]))
	if len(fields) <= 19 || fields[0] == "Z" || fields[0] == "X" {
		return ProcessIdentity{}, os.ErrNotExist
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return ProcessIdentity{}, errors.New("invalid process start time")
	}
	exe, err := os.Readlink(prefix + "/exe")
	if err != nil {
		return ProcessIdentity{}, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ProcessIdentity{}, err
	}
	return ProcessIdentity{PID: pid, StartTime: start, BootID: strings.TrimSpace(string(boot)), Exe: exe}, nil
}

// HasRunningUpdater checks the fixed production executable. Any existing
// updater makes the next interval a skip; no old process is adopted or waited.
func HasRunningUpdater() (bool, error) { return hasRunningUpdater(updaterBinary) }

func hasRunningUpdater(executable string) (bool, error) {
	canonical, err := filepath.EvalSymlinks(executable)
	if err == nil {
		executable = canonical
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false, errors.New("cannot inspect running updater processes")
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		exe, err := os.Readlink("/proc/" + entry.Name() + "/exe")
		if err == nil && strings.TrimSuffix(exe, " (deleted)") == executable {
			return true, nil
		}
	}
	return false, nil
}

func lockFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.New("cannot open hawkBit process lock")
	}
	if err = f.Chmod(0600); err == nil {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	}
	if err != nil {
		f.Close()
		return nil, errors.New("another hawkBit controller is active")
	}
	return f, nil
}

func openLog(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.New("cannot open updater log")
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("invalid updater log")
	}
	if s, ok := info.Sys().(*syscall.Stat_t); !ok || s.Nlink != 1 || s.Uid != uint32(os.Geteuid()) {
		f.Close()
		return nil, errors.New("invalid updater log ownership")
	}
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return nil, errors.New("cannot protect updater log")
	}
	return f, nil
}

// Copytruncate preserves the inode already opened by the updater. Core keeps
// only the last 64 KiB per rotation, but an active writer can temporarily
// exceed the threshold, and Core downtime has no hard log-size guarantee.
func rotateLog(f *os.File, path string) error {
	return copytruncateLog(f, path, false)
}

func rotateLogForRun(f *os.File, path string) error {
	return copytruncateLog(f, path, true)
}

func copytruncateLog(f *os.File, path string, freshRun bool) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() == 0 || (!freshRun && info.Size() <= logLimit) {
		return nil
	}
	length := min(info.Size(), int64(logLimit))
	data := make([]byte, length)
	n, err := f.ReadAt(data, info.Size()-length)
	if err != nil && err != io.EOF {
		return err
	}
	if err := atomicWrite(path+".1", data[:n]); err != nil {
		return err
	}
	return f.Truncate(0)
}
