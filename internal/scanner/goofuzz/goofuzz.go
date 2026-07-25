package goofuzz

// goofuzz.go — wrapper for the GooFuzz bash-script tool.
//
// GooFuzz (https://github.com/m3n0sd0n4ld/GooFuzz) performs OSINT-based
// fuzzing via Google Custom Search API — no requests reach the target server.
//
// Requirements:
//   - `GooFuzz` binary in PATH  (installed in Dockerfile)
//   - A Google Custom Search Engine ID  (GOOFUZZ_CX_ID env var or Options.CXID)
//   - A Google API key                  (GOOFUZZ_API_KEY env var or Options.APIKey)
//   - Custom Search API enabled at console.cloud.google.com with no referrer restriction
//
// IMPORTANT: GooFuzz only supports ONE mode per invocation.
// This wrapper runs each mode as a separate subprocess and merges results.
//   - Extensions  (-e pdf,doc,zip)        → one run
//   - Wordlist    (-w admin,login,backup)  → one run
//   - Subdomains  (-s)                     → one run
//   - Content     (-c <keyword>)           → one run

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/logger"
	"github.com/h0tak88r/AutoAR/internal/utils"
)

const goofuzzTimeout = 30 * time.Minute

// Options controls a GooFuzz run.
type Options struct {
	Target     string // domain / IP (required)
	CXID       string // Google Programmable Search Engine ID
	APIKey     string // Google Custom Search API key
	Extensions string // comma-separated extensions (e.g. "pdf,doc,bak")
	Wordlist   string // comma-separated paths/words OR path to a wordlist file
	Subdomains bool   // enumerate subdomains (-s)
	Content    string // search for pages containing this keyword (-c)
	Pages      int    // number of result pages per query (default 1)
	Exclusions string // comma-separated subdomains to exclude (-x)
	Delay      int    // delay in seconds between requests (-d)
	Proxy      string // proxy URL (-r)
}

// Result holds paths to the output files produced by GooFuzz.
type Result struct {
	BaseDir    string
	OutputFile string // merged plain-text results file
	LineCount  int
}

// modeRun describes a single GooFuzz invocation for one mode.
type modeRun struct {
	label string   // e.g. "extensions:php,txt"
	args  []string // mode-specific args (NOT including -t/-k/-p/-x/-d/-r/-o)
}

// apiErrorPhrases lists substrings that indicate a Google API / argument error.
var apiErrorPhrases = []string{
	"API error",
	"accessNotConfigured",
	"has not been used",
	"is disabled",
	"blocked",
	"PERMISSION_DENIED",
	"Daily Limit",
	"quota",
	"invalid api key",
	"API key not valid",
	"does not have the access",
	"referer",
	"ipRefererBlocked",
	"missing or invalid argument",
	"Error, missing or invalid",
}

// isAPIError returns true when the output line signals a Google API or argument problem.
func isAPIError(line string) bool {
	low := strings.ToLower(line)
	for _, phrase := range apiErrorPhrases {
		if strings.Contains(low, strings.ToLower(phrase)) {
			return true
		}
	}
	return false
}

// isResultLine returns true for lines that are actual results (not banner/status lines).
func isResultLine(line string) bool {
	if line == "" {
		return false
	}
	// Skip GooFuzz banner and status lines
	prefixes := []string{"***", "* ", "Target:", "[!]", "[+]", "[-]", "Usage:", "-h ", "-k ", "-w ", "-e ", "-t ", "-p ", "-x ", "-d ", "-s", "-c ", "-o ", "-r ", "Examples:", "GooFuzz "}
	for _, p := range prefixes {
		if strings.HasPrefix(line, p) {
			return false
		}
	}
	return true
}

// stripANSI removes ANSI escape sequences for clean log output.
func stripANSI(s string) string {
	var b strings.Builder
	inEsc := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\x1b' {
			inEsc = true
			continue
		}
		if inEsc {
			if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
				inEsc = false
			}
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// Run invokes GooFuzz for each requested mode separately (GooFuzz only supports
// one mode per invocation) and merges all results into a single output file.
func Run(opts Options) (*Result, error) {
	log := logger.GetLogger()

	// ── 1. Pre-flight checks ────────────────────────────────────────────────

	binPath, err := exec.LookPath("GooFuzz")
	if err != nil {
		return nil, fmt.Errorf("GooFuzz not found in PATH; ensure it is installed in the Docker image")
	}

	if opts.Target == "" {
		return nil, fmt.Errorf("target domain is required")
	}

	cxID := opts.CXID
	apiKey := opts.APIKey
	if cxID == "" {
		cxID = os.Getenv("GOOFUZZ_CX_ID")
	}
	if apiKey == "" {
		apiKey = os.Getenv("GOOFUZZ_API_KEY")
	}
	if cxID == "" || apiKey == "" {
		return nil, fmt.Errorf(
			"Google CX ID and API key are required; " +
				"set GOOFUZZ_CX_ID / GOOFUZZ_API_KEY env vars or pass via request body",
		)
	}

	// ── 2. Output directory ─────────────────────────────────────────────────

	resultsRoot := os.Getenv("AUTOAR_RESULTS_DIR")
	if resultsRoot == "" {
		resultsRoot = "new-results"
	}
	scanID := utils.GetCurrentScanID()
	var baseDir string
	if scanID != "" {
		baseDir = utils.GetScanResultsDir(scanID)
	} else {
		baseDir = filepath.Join(resultsRoot, "goofuzz", utils.SanitizeTargetSegment(opts.Target))
	}
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create output dir: %w", err)
	}

	// ── 3. Temporary keys file ──────────────────────────────────────────────
	// Use /tmp so path has no spaces and is always accessible.

	keysFile := filepath.Join(os.TempDir(), fmt.Sprintf(".goofuzz_keys_%d.tmp", time.Now().UnixNano()))
	if err := os.WriteFile(keysFile, []byte(cxID+","+apiKey+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("failed to write GooFuzz keys file: %w", err)
	}
	defer os.Remove(keysFile)

	// ── 4. Build mode list ──────────────────────────────────────────────────
	// GooFuzz supports ONLY ONE mode flag per run.

	pages := opts.Pages
	if pages <= 0 {
		pages = 1
	}

	var modes []modeRun
	if opts.Extensions != "" {
		modes = append(modes, modeRun{
			label: "extensions:" + opts.Extensions,
			args:  []string{"-e", opts.Extensions},
		})
	}
	if opts.Wordlist != "" {
		modes = append(modes, modeRun{
			label: "wordlist:" + opts.Wordlist,
			args:  []string{"-w", opts.Wordlist},
		})
	}
	if opts.Subdomains {
		modes = append(modes, modeRun{
			label: "subdomains",
			args:  []string{"-s"},
		})
	}
	if opts.Content != "" {
		modes = append(modes, modeRun{
			label: "content:" + opts.Content,
			args:  []string{"-c", opts.Content},
		})
	}

	// Default: run subdomains if no mode was selected
	if len(modes) == 0 {
		modes = append(modes, modeRun{label: "subdomains", args: []string{"-s"}})
	}

	// ── 5. Run each mode separately and collect results ─────────────────────

	outputFile := filepath.Join(baseDir, "goofuzz-results.txt")
	outF, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	defer outF.Close()

	totalLines := 0

	for i, mode := range modes {
		log.Infof("[goofuzz] [%d/%d] Running mode: %s", i+1, len(modes), mode.label)

		// Build per-mode output file
		modeOutFile := filepath.Join(baseDir, fmt.Sprintf("goofuzz-%d-%s.tmp", i, strings.ReplaceAll(mode.label, ":", "_")))
		defer os.Remove(modeOutFile)

		// Base args: -t <target> -k <keysfile> -p <pages> [-x excl] [-d delay] [-r proxy] -o <output>
		args := []string{
			"-t", opts.Target,
			"-k", keysFile,
			"-p", fmt.Sprintf("%d", pages),
		}
		if opts.Exclusions != "" {
			args = append(args, "-x", opts.Exclusions)
		}
		if opts.Delay > 0 {
			args = append(args, "-d", fmt.Sprintf("%d", opts.Delay))
		}
		if opts.Proxy != "" {
			args = append(args, "-r", opts.Proxy)
		}
		// Add the single mode flag
		args = append(args, mode.args...)
		// Add output file
		args = append(args, "-o", modeOutFile)

		ctx, cancel := context.WithTimeout(context.Background(), goofuzzTimeout)

		cmd := exec.CommandContext(ctx, binPath, args...)

		stdoutPipe, pErr := cmd.StdoutPipe()
		if pErr != nil {
			cancel()
			return nil, fmt.Errorf("goofuzz stdout pipe: %w", pErr)
		}
		stderrPipe, pErr := cmd.StderrPipe()
		if pErr != nil {
			cancel()
			return nil, fmt.Errorf("goofuzz stderr pipe: %w", pErr)
		}

		if sErr := cmd.Start(); sErr != nil {
			cancel()
			return nil, fmt.Errorf("goofuzz start: %w", sErr)
		}

		var (
			apiErrMsg string
			mu        sync.Mutex
		)

		readPipe := func(r io.Reader) {
			sc := bufio.NewScanner(r)
			for sc.Scan() {
				raw := sc.Text()
				clean := strings.TrimSpace(stripANSI(raw))
				if clean == "" {
					continue
				}
				log.Infof("[goofuzz:%s] %s", mode.label, clean)
				mu.Lock()
				if apiErrMsg == "" && isAPIError(clean) {
					apiErrMsg = clean
				}
				mu.Unlock()
			}
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); readPipe(stdoutPipe) }()
		go func() { defer wg.Done(); readPipe(stderrPipe) }()
		wg.Wait()
		cmd.Wait()
		cancel()

		mu.Lock()
		detectedErr := apiErrMsg
		mu.Unlock()

		if detectedErr != "" {
			hint := buildHint(detectedErr)
			return nil, fmt.Errorf("GooFuzz Google API error (mode=%s): %s%s", mode.label, detectedErr, hint)
		}

		// Append mode results to merged output file
		if modeLines, readErr := appendModeResults(outF, modeOutFile, mode.label); readErr == nil {
			totalLines += modeLines
			if modeLines > 0 {
				log.Infof("[goofuzz:%s] %d result(s) found", mode.label, modeLines)
			} else {
				log.Infof("[goofuzz:%s] 0 results found", mode.label)
			}
		}
	}

	outF.Close()

	log.Infof("[goofuzz] Done — %d total result lines → %s", totalLines, outputFile)

	// ── 6. Index artifact ───────────────────────────────────────────────────

	if scanID != "" {
		if _, idxErr := utils.IndexExistingResultFile(scanID, outputFile); idxErr != nil {
			log.Warnf("[goofuzz] Failed to index result file: %v", idxErr)
		}
	}

	return &Result{
		BaseDir:    baseDir,
		OutputFile: outputFile,
		LineCount:  totalLines,
	}, nil
}

// appendModeResults reads GooFuzz's per-mode -o file (or falls back to stdout capture),
// filters result lines, writes them to the merged output file, and returns the line count.
func appendModeResults(outF *os.File, modeOutFile, label string) (int, error) {
	f, err := os.Open(modeOutFile)
	if err != nil {
		// GooFuzz didn't create the file (0 results) — that's fine
		return 0, nil
	}
	defer f.Close()

	count := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fmt.Fprintln(outF, line)
		count++
	}
	return count, nil
}

// buildHint returns an actionable fix hint based on the error message.
func buildHint(msg string) string {
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "referer") || strings.Contains(low, "iprefererblocked"):
		return " → Remove HTTP referrer restriction: console.cloud.google.com/apis/credentials → edit API key → Application restrictions → None"
	case strings.Contains(low, "has not been used") || strings.Contains(low, "is disabled") || strings.Contains(low, "accessnotconfigured") || strings.Contains(low, "does not have the access"):
		return " → Enable Custom Search API: https://console.cloud.google.com/apis/library/customsearch.googleapis.com"
	case strings.Contains(low, "daily limit") || strings.Contains(low, "quota"):
		return " → Google Custom Search API daily quota exceeded (100 free queries/day)"
	case strings.Contains(low, "invalid api key") || strings.Contains(low, "api key not valid"):
		return " → Check GOOFUZZ_API_KEY value in .env or dashboard settings"
	case strings.Contains(low, "missing or invalid argument") || strings.Contains(low, "error, missing"):
		return " → GooFuzz argument error — check that only one mode flag is used per scan"
	default:
		return " → Check that Custom Search API is enabled and billing is active at console.cloud.google.com"
	}
}

func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	count := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			count++
		}
	}
	return count
}
