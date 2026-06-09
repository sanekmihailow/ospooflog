package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
)

// Debug verbosity breakpoints. Levels are cumulative (1..10); these name the
// two where behaviour changes beyond "print more".
const (
	dbgCaller = 9  // prefix each line with the Go caller file:line; stack on error
	dbgStats  = 10 // dump runtime mem/goroutine stats at exit
)

// dbg is the process-wide debug tracer, set once in run() from --debug (or the
// config). A nil tracer (or level 0) means tracing is off — at() is a no-op, so
// trace points can call it unconditionally without guarding.
var dbg *debugLog

type debugLog struct {
	level int
	w     io.Writer
}

func (d *debugLog) on(level int) bool { return d != nil && level <= d.level }

// at writes one trace line when verbosity reaches level. From dbgCaller up it
// prefixes the Go caller's file:line (slog-style) so high-verbosity output
// points back at the emitting line.
func (d *debugLog) at(level int, format string, args ...any) {
	if !d.on(level) {
		return
	}
	prefix := "debug: "
	if d.level >= dbgCaller {
		if _, file, line, ok := runtime.Caller(1); ok {
			prefix = fmt.Sprintf("debug %s:%d: ", filepath.Base(file), line)
		}
	}
	fmt.Fprintf(d.w, prefix+format+"\n", args...)
}

// runtimeStats dumps Go runtime memory/goroutine counters (level dbgStats).
func (d *debugLog) runtimeStats() {
	if !d.on(dbgStats) {
		return
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	d.at(dbgStats, "runtime: goroutines=%d alloc=%dKiB total-alloc=%dKiB sys=%dKiB gc=%d",
		runtime.NumGoroutine(), ms.Alloc/1024, ms.TotalAlloc/1024, ms.Sys/1024, ms.NumGC)
}

// startProfiling writes a runtime/trace plus CPU and (on stop) heap pprof into
// dir — the binary Go artifacts read with `go tool trace` / `go tool pprof`.
// Returns a stop func to defer. Triggered by --debug-out, independent of the
// text verbosity level.
func startProfiling(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	tracePath := filepath.Join(dir, "ospooflog.trace")
	cpuPath := filepath.Join(dir, "ospooflog.cpu.pprof")
	memPath := filepath.Join(dir, "ospooflog.mem.pprof")

	tf, err := os.Create(tracePath)
	if err != nil {
		return nil, err
	}
	cf, err := os.Create(cpuPath)
	if err != nil {
		tf.Close()
		return nil, err
	}
	if err := trace.Start(tf); err != nil {
		cf.Close()
		tf.Close()
		return nil, err
	}
	if err := pprof.StartCPUProfile(cf); err != nil {
		trace.Stop()
		cf.Close()
		tf.Close()
		return nil, err
	}
	dbg.at(1, "debug-out: runtime/trace → %s, cpu → %s, mem → %s", tracePath, cpuPath, memPath)

	return func() {
		pprof.StopCPUProfile()
		trace.Stop()
		cf.Close()
		tf.Close()
		if mf, err := os.Create(memPath); err == nil {
			runtime.GC()
			_ = pprof.WriteHeapProfile(mf)
			mf.Close()
		}
	}, nil
}
