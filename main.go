package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
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

type record struct {
	ID      uint32
	PID     uint32
	Count   uint64
	TotalNs uint64
	MaxNs   uint64
}

type outputRecord struct {
	SyscallID   uint32  `json:"syscall_id"`
	SyscallName string  `json:"syscall_name"`
	PID         uint32  `json:"pid"`
	Count       uint64  `json:"count"`
	AvgUs       float64 `json:"avg_us"`
	MaxUs       float64 `json:"max_us"`
}

func syscallName(id uint32) string {
	name := syscallNames[id]
	if name == "" {
		return fmt.Sprintf("sys_%d", id)
	}
	return name
}

func toOutputRecords(records []record) []outputRecord {
	out := make([]outputRecord, 0, len(records))
	for _, r := range records {
		out = append(out, outputRecord{
			SyscallID:   r.ID,
			SyscallName: syscallName(r.ID),
			PID:         r.PID,
			Count:       r.Count,
			AvgUs:       float64(r.TotalNs) / float64(r.Count) / 1000.0,
			MaxUs:       float64(r.MaxNs) / 1000.0,
		})
	}
	return out
}

func printText(records []record) {
	currentID := uint32(^uint32(0))

	for _, r := range records {
		if r.ID != currentID {
			currentID = r.ID
			fmt.Printf("\n%s\n", syscallName(r.ID))
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

func printCSV(records []record) {
	writer := csv.NewWriter(os.Stdout)
	defer writer.Flush()

	if err := writer.Write([]string{"syscall_id", "syscall_name", "pid", "count", "avg_us", "max_us"}); err != nil {
		log.Fatalf("write csv header: %v", err)
	}

	for _, r := range toOutputRecords(records) {
		row := []string{
			fmt.Sprintf("%d", r.SyscallID),
			r.SyscallName,
			fmt.Sprintf("%d", r.PID),
			fmt.Sprintf("%d", r.Count),
			fmt.Sprintf("%.2f", r.AvgUs),
			fmt.Sprintf("%.2f", r.MaxUs),
		}
		if err := writer.Write(row); err != nil {
			log.Fatalf("write csv row: %v", err)
		}
	}

	if err := writer.Error(); err != nil {
		log.Fatalf("flush csv: %v", err)
	}
}

func printJSON(records []record) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(toOutputRecords(records)); err != nil {
		log.Fatalf("write json: %v", err)
	}
}

func main() {
	outputFormat := flag.String("output", "text", "output format: text, csv, or json")
	flag.Parse()

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

	switch *outputFormat {
	case "text":
		printText(records)
	case "csv":
		printCSV(records)
	case "json":
		printJSON(records)
	default:
		log.Fatalf("invalid output format %q: use text, csv, or json", *outputFormat)
	}
}
