package api

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/h0tak88r/AutoAR/internal/db"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

var (
	ActiveScans = make(map[string]*ScanInfo)
	ScansMutex  sync.RWMutex
)

func init() {
	// Register the cancel-check hook so utils.IsScanCancelled (called from
	// RunWorkflowPhase) can inspect the api-layer CancelRequested flag without
	// creating a circular import (utils → api is not allowed).
	utils.RegisterCancelChecker(func(scanID string) bool {
		ScansMutex.RLock()
		defer ScansMutex.RUnlock()
		si, ok := ActiveScans[scanID]
		return ok && si != nil && si.CancelRequested
	})

	// Register the pause-check hook so RunWorkflowPhase can check pause state.
	utils.RegisterPauseChecker(func(scanID string) bool {
		ScansMutex.RLock()
		defer ScansMutex.RUnlock()
		si, ok := ActiveScans[scanID]
		return ok && si != nil && si.PauseRequested
	})

	// Register the pause-waiter hook so RunWorkflowPhase can block between phases.
	utils.RegisterPauseWaiter(func(scanID string) bool {
		return WaitIfPaused(scanID)
	})
}

type ScanInfo struct {
	ScanID      string
	Type        string
	ScanType    string // For API compatibility
	Target      string
	Status      string
	StartTime   time.Time
	StartedAt   time.Time // For API compatibility
	CompletedAt *time.Time
	Command     string
	CancelFunc  context.CancelFunc // Function to cancel the scan
	ExecCmd     *exec.Cmd          `json:"-"` // API executeScan: child process (kill / pause via signals)
	CancelRequested bool           `json:"-"` // API: user requested stop; Wait() will mark cancelled

	// Pause/Resume support for in-process goroutine scans
	PauseRequested bool        `json:"-"` // true while paused
	pauseCh        chan struct{} `json:"-"` // closed to signal resume

	// Progress tracking
	CurrentPhase    int       // Current phase number (1-based)
	TotalPhases     int       // Total number of phases
	PhaseName       string    // Name of current phase
	PhaseStartTime  time.Time // When current phase started
	CompletedPhases []string  // List of completed phase names
	FailedPhases    []string  // List of failed phase names

	// Statistics
	FilesUploaded int       // Number of files uploaded
	ErrorCount    int       // Number of errors encountered
	LastUpdate    time.Time // Last progress update time
}

// CancelScanByID stops a running scan.
// It immediately marks the in-memory status as "cancelling" and updates the DB
// so the dashboard shows feedback right away, before the goroutine actually exits.
func CancelScanByID(id string) error {
	ScansMutex.Lock()
	scan, ok := ActiveScans[id]
	if !ok {
		ScansMutex.Unlock()
		return fmt.Errorf("scan %s not found or not active", id)
	}
	scan.CancelRequested = true
	scan.Status = "cancelling"

	// If paused, resume first so the goroutine can observe CancelRequested.
	if scan.PauseRequested {
		scan.PauseRequested = false
		ch := scan.pauseCh
		scan.pauseCh = nil
		if ch != nil {
			close(ch)
		}
	}
	ScansMutex.Unlock()

	// Persist "cancelling" status immediately so UI shows feedback at once.
	_ = db.UpdateScanStatus(id, "cancelling")

	// If it's a child process, kill the entire process group so that
	// sub-tools (nuclei, subfinder, etc.) are also terminated.
	if scan.ExecCmd != nil && scan.ExecCmd.Process != nil {
		pid := scan.ExecCmd.Process.Pid
		log.Printf("[INFO] Killing child process group for scan %s (pid %d)", id, pid)
		pgid, pgidErr := syscall.Getpgid(pid)
		if pgidErr == nil {
			_ = syscall.Kill(-pgid, syscall.SIGTERM)
		} else {
			_ = scan.ExecCmd.Process.Signal(syscall.SIGTERM)
		}
		go func() {
			timer := time.NewTimer(2 * time.Second)
			defer timer.Stop()
			select {
			case <-timer.C:
				if pgidErr == nil {
					_ = syscall.Kill(-pgid, syscall.SIGKILL)
				} else {
					_ = scan.ExecCmd.Process.Kill()
				}
			}
		}()
	}

	// Cancel the context — this is the primary signal for in-process scans.
	if scan.CancelFunc != nil {
		scan.CancelFunc()
	}

	return nil
}

// PauseScanByID pauses a running scan.
// For child-process scans: sends SIGSTOP to the process group.
// For in-process goroutine scans: sets PauseRequested so RunWorkflowPhase
// blocks at the next phase boundary.
func PauseScanByID(id string) error {
	ScansMutex.Lock()
	scan, ok := ActiveScans[id]
	if !ok {
		ScansMutex.Unlock()
		return fmt.Errorf("scan %s not found or not active", id)
	}
	if scan.Status == "paused" || scan.PauseRequested {
		ScansMutex.Unlock()
		return fmt.Errorf("scan %s is already paused", id)
	}
	if scan.CancelRequested || scan.Status == "cancelling" {
		ScansMutex.Unlock()
		return fmt.Errorf("scan %s is being cancelled", id)
	}

	// --- Child-process scan ---
	if scan.ExecCmd != nil && scan.ExecCmd.Process != nil {
		pid := scan.ExecCmd.Process.Pid
		scan.Status = "paused"
		ScansMutex.Unlock()
		log.Printf("[INFO] Pausing scan %s (pid %d) process group", id, pid)
		_ = db.UpdateScanStatus(id, "paused")
		pgid, pgidErr := syscall.Getpgid(pid)
		if pgidErr == nil {
			return syscall.Kill(-pgid, syscall.SIGSTOP)
		}
		return scan.ExecCmd.Process.Signal(syscall.SIGSTOP)
	}

	// --- In-process goroutine scan ---
	// Create a new pause channel; RunWorkflowPhase will block on it.
	ch := make(chan struct{})
	scan.PauseRequested = true
	scan.pauseCh = ch
	scan.Status = "paused"
	ScansMutex.Unlock()

	log.Printf("[INFO] Pausing in-process scan %s at next phase boundary", id)
	_ = db.UpdateScanStatus(id, "paused")
	return nil
}

// ResumeScanByID resumes a paused scan.
// For child-process scans: sends SIGCONT to the process group.
// For in-process goroutine scans: closes the pause channel so blocked
// goroutines unblock.
func ResumeScanByID(id string) error {
	ScansMutex.Lock()
	scan, ok := ActiveScans[id]
	if !ok {
		ScansMutex.Unlock()
		return fmt.Errorf("scan %s not found or not active", id)
	}
	if !scan.PauseRequested && scan.Status != "paused" {
		ScansMutex.Unlock()
		return fmt.Errorf("scan %s is not paused", id)
	}

	// --- Child-process scan ---
	if scan.ExecCmd != nil && scan.ExecCmd.Process != nil {
		pid := scan.ExecCmd.Process.Pid
		scan.Status = "running"
		scan.PauseRequested = false
		ScansMutex.Unlock()
		log.Printf("[INFO] Resuming scan %s (pid %d) process group", id, pid)
		_ = db.UpdateScanStatus(id, "running")
		pgid, pgidErr := syscall.Getpgid(pid)
		if pgidErr == nil {
			return syscall.Kill(-pgid, syscall.SIGCONT)
		}
		return scan.ExecCmd.Process.Signal(syscall.SIGCONT)
	}

	// --- In-process goroutine scan ---
	ch := scan.pauseCh
	scan.PauseRequested = false
	scan.pauseCh = nil
	scan.Status = "running"
	ScansMutex.Unlock()

	log.Printf("[INFO] Resuming in-process scan %s", id)
	_ = db.UpdateScanStatus(id, "running")
	if ch != nil {
		close(ch) // unblock WaitIfPaused
	}
	return nil
}

// WaitIfPaused blocks the calling goroutine while the scan is paused.
// It returns true if the scan was paused (and is now resumed), false if not paused.
// Called from RunWorkflowPhase between phases.
func WaitIfPaused(scanID string) bool {
	ScansMutex.RLock()
	scan, ok := ActiveScans[scanID]
	if !ok || !scan.PauseRequested {
		ScansMutex.RUnlock()
		return false
	}
	ch := scan.pauseCh
	ScansMutex.RUnlock()

	if ch == nil {
		return false
	}
	// Block until resume (channel closed) or scan gone.
	<-ch
	return true
}

// ScanIsActiveInMemory checks if a scan ID is currently tracked as running/paused
func ScanIsActiveInMemory(id string) bool {
	ScansMutex.RLock()
	defer ScansMutex.RUnlock()
	scan, ok := ActiveScans[id]
	if !ok {
		return false
	}
	st := strings.ToLower(scan.Status)
	return st == "running" || st == "starting" || st == "paused" || st == "cancelling"
}
