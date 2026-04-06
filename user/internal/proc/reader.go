package proc

import (
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