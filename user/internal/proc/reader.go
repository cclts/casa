package proc

import (
    "fmt"
    "os"
    "strconv"
)

func ReadComm(pid int) (string, error) {
    data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
    if err != nil {
        return "", err
    }
    return string(data[:len(data)-1]), nil // remove \n
}

func ReadPPID(pid int) (int, error) {
    data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
    if err != nil {
        return 0, err
    }

    var (
        pidVal int
        comm   string
        state  string
        ppid   int
    )

    fmt.Sscanf(string(data), "%d %s %s %d", &pidVal, &comm, &state, &ppid)
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