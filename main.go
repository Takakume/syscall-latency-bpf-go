package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"

	"github.com/cilium/ebpf/link"
)

var syscallNames = map[uint32]string{
	0:   "read",
	1:   "write",
	2:   "open",
	3:   "close",
	9:   "mmap",
	39:  "getpid",
	57:  "fork",
	60:  "exit",
	63:  "uname",
	257: "openat",
	262: "newfstatat",
}

func main() {
	objs := syscallObjects{}
	if err := loadSyscallObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	tpEnter, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.HandleSysEnter, nil)
	if err != nil {
		log.Fatalf("attach sys_enter: %v", err)
	}
	defer tpEnter.Close()

	tpExit, err := link.Tracepoint("raw_syscalls", "sys_exit", objs.HandleSysExit, nil)
	if err != nil {
		log.Fatalf("attach sys_exit: %v", err)
	}
	defer tpExit.Close()

	fmt.Println("Running... Press Ctrl+C to stop.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig

	fmt.Println("\nCollecting stats...\n")

	type record struct {
		ID      uint32
		PID     uint32
		Count   uint64
		TotalNs uint64
		MaxNs   uint64
	}

	var records []record

	iter := objs.Stats.Iterate()
	var key syscallKeyT
	var val syscallStatsT

	for iter.Next(&key, &val) {
		records = append(records, record{
			ID:      key.Id,
			PID:     key.Pid,
			Count:   val.Count,
			TotalNs: val.TotalNs,
			MaxNs:   val.MaxNs,
		})
	}

	if err := iter.Err(); err != nil {
		log.Fatalf("map iteration: %v", err)
	}

	sort.Slice(records, func(i, j int) bool {
		if records[i].ID == records[j].ID {
			return records[i].PID < records[j].PID
		}
		return records[i].ID < records[j].ID
	})

	currentID := uint32(^uint32(0))

	for _, r := range records {
		if r.ID != currentID {
			currentID = r.ID
			name := syscallNames[r.ID]
			if name == "" {
				name = fmt.Sprintf("sys_%d", r.ID)
			}
			fmt.Printf("\n%s\n", name)
			fmt.Println("------------------------------------------------------------")
			fmt.Printf("%-10s %-10s %-12s %-12s\n", "PID", "COUNT", "AVG(us)", "MAX(us)")
		}

		avgUs := float64(r.TotalNs) / float64(r.Count) / 1000.0
		maxUs := float64(r.MaxNs) / 1000.0

		fmt.Printf("%-10d %-10d %-12.2f %-12.2f\n",
			r.PID,
			r.Count,
			avgUs,
			maxUs,
		)
	}
}

