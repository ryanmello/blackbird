package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type Finding struct {
	OSV          string `json:"osv"`
	FixedVersion string `json:"fixed_version"`
}

// runCommand executes a shell command and prints its output.
// If the command fails, it returns an error.
func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	fmt.Printf("$ %s %s\n%s\n", name, strings.Join(args, " "), string(output))
	if err != nil {
		return fmt.Errorf("command %s failed: %v", name, err)
	}
	return nil
}

func main() {
	workspace := "/github/workspace"
	if len(os.Args) > 1 {
		workspace = os.Args[1]
	}

	// Change to workspace directory
	if err := os.Chdir(workspace); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to switch to workspace %s: %v\n", workspace, err)
		os.Exit(1)
	}

	// Ensure Go and dependencies are ready
	steps := [][]string{
		{"go", "version"},
		{"go", "list", "-m", "all"},
		{"go", "mod", "download"},
	}
	for _, step := range steps {
		if err := runCommand(step[0], step[1:]...); err != nil {
			os.Exit(1)
		}
	}

	// Run govulncheck
	cmd := exec.Command("govulncheck", "-format=json", "./...")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ govulncheck failed: %v\n%s\n", err, stderr.String())
		os.Exit(1)
	}

	// Parse JSON output and collect findings
	vulns := make(map[string]string)
	for _, raw := range strings.Split(stdout.String(), "\n}\n{") {
		// Normalize line-delimited JSON object
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !strings.HasPrefix(raw, "{") {
			raw = "{" + raw
		}
		if !strings.HasSuffix(raw, "}") {
			raw = raw + "}"
		}

		var wrapper map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &wrapper); err != nil {
			continue
		}

		if data, ok := wrapper["finding"]; ok {
			var f Finding
			if err := json.Unmarshal(data, &f); err == nil && f.OSV != "" {
				vulns[f.OSV] = f.FixedVersion
			}
		}
	}

	// Print summary
	if len(vulns) > 0 {
		fmt.Printf("🚨 %d vulnerabilities found:\n", len(vulns))
		for id, fix := range vulns {
			fmt.Printf("- [%s](https://pkg.go.dev/vuln/%s) — Fixed in: %s\n", id, id, fix)
		}
		os.Exit(1)
	}

	fmt.Println("✅ No vulnerabilities found!")
}
