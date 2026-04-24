package proc

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ReadComm reads the command name for a process from /proc.
func ReadComm(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(data)), nil
}

// ReadPPID parses /proc/<pid>/stat and extracts the parent pid field.
func ReadPPID(pid int) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}

	end := bytes.LastIndexByte(data, ')')
	if end == -1 {
		return 0, fmt.Errorf("invalid stat format")
	}

	rest := string(data[end+2:]) // skip ") "

	fields := strings.Fields(rest)
	if len(fields) < 2 {
		return 0, fmt.Errorf("stat fields too short")
	}

	// fields[0] = state
	// fields[1] = ppid
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, err
	}

	return ppid, nil
}

// ListPIDs returns the numeric process directories visible under /proc.
func ListPIDs() ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	var pids []int
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err == nil {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// ReadExe resolves the current executable path for a process.
func ReadExe(pid int) (string, error) {
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", err
	}
	return path, nil
}

var (
	bootTimeOnce sync.Once
	bootTime     time.Time
	bootTimeErr  error
)

// ReadBootTime reads the system boot time from /proc/stat and caches it for reuse.
func ReadBootTime() (time.Time, error) {
	bootTimeOnce.Do(func() {
		data, err := os.ReadFile("/proc/stat")
		if err != nil {
			bootTimeErr = err
			return
		}

		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(line, "btime ") {
				continue
			}

			fields := strings.Fields(line)
			if len(fields) != 2 {
				bootTimeErr = fmt.Errorf("invalid btime format")
				return
			}

			secs, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				bootTimeErr = err
				return
			}

			bootTime = time.Unix(secs, 0)
			return
		}

		bootTimeErr = fmt.Errorf("btime not found in /proc/stat")
	})

	return bootTime, bootTimeErr
}

// EventTimeFromKtime converts a monotonic boot-relative kernel timestamp into wall-clock time.
func EventTimeFromKtime(ktimeNS uint64) (time.Time, error) {
	boot, err := ReadBootTime()
	if err != nil {
		return time.Time{}, err
	}

	return boot.Add(time.Duration(ktimeNS)), nil
}

// FormatEventTime renders an event time in a stable human-readable form.
func FormatEventTime(ts time.Time) string {
	if ts.IsZero() {
		return ""
	}

	return ts.Local().Format(time.RFC3339Nano)
}

// ReadProcSecurityDetails returns the raw CapEff mask and seccomp mode.
func ReadProcSecurityDetails(pid int) (uint64, int, error) {
	path := fmt.Sprintf("/proc/%d/status", pid)

	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()

	var capVal uint64
	var seccompMode int
	var foundCap, foundSeccomp bool

	// The status file is line-oriented, so a scanner keeps parsing simple and cheap.
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "CapEff:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, err := strconv.ParseUint(fields[1], 16, 64)
				if err == nil {
					capVal = v
					foundCap = true
				}
			}
		}

		if strings.HasPrefix(line, "Seccomp:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, err := strconv.Atoi(fields[1])
				if err == nil {
					seccompMode = v
					foundSeccomp = true
				}
			}
		}

		if foundCap && foundSeccomp {
			break
		}
	}

	if !foundCap && !foundSeccomp {
		return 0, 0, fmt.Errorf("missing CapEff and Seccomp in /proc/%d/status", pid)
	}
	if !foundCap {
		return 0, 0, fmt.Errorf("missing CapEff in /proc/%d/status", pid)
	}
	if !foundSeccomp {
		return 0, 0, fmt.Errorf("missing Seccomp in /proc/%d/status", pid)
	}

	return capVal, seccompMode, nil
}

