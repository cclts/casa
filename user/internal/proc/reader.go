package proc

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func ReadComm(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(data)), nil
}

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

func ReadExe(pid int) (string, error) {
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", err
	}
	return path, nil
}

const (
	CAP_SYS_ADMIN  = 21
	CAP_SYS_PTRACE = 19
	CAP_NET_ADMIN  = 12
	CAP_NET_RAW    = 13
)

const highRiskMask = (1 << CAP_SYS_ADMIN) |
	(1 << CAP_SYS_PTRACE) |
	(1 << CAP_NET_ADMIN) |
	(1 << CAP_NET_RAW)

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

	if !foundCap || !foundSeccomp {
		return 0, 0, fmt.Errorf("incomplete proc status")
	}

	return capVal, seccompMode, nil
}

// ReadProcSecurity returns whether the process has high-risk capabilities and
// whether seccomp is enabled.
func ReadProcSecurity(pid int) (bool, bool, error) {
	capVal, seccompMode, err := ReadProcSecurityDetails(pid)
	if err != nil {
		return false, false, err
	}

	hasHighRiskCaps := (capVal & highRiskMask) != 0
	return hasHighRiskCaps, seccompMode != 0, nil
}
