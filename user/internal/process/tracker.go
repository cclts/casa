package process

type Tracker struct {
    tracked map[uint32]bool
}

func NewTracker() *Tracker {
    return &Tracker{
        tracked: make(map[uint32]bool),
    }
}

func (t *Tracker) Add(pid uint32) {
    t.tracked[pid] = true
}

func (t *Tracker) IsTracked(pid uint32) bool {
    return t.tracked[pid]
}