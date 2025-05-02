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

func main() {
	if err := os.Chdir("/github/workspace"); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to switch to /github/workspace: %v\n", err)
		os.Exit(1)
	}

	steps := [][]string{
		{"go", "version"},
		// {"go", "list", "-m", "all"},
		{"go", "mod", "download"},
	}

	for _, step := range steps {
		if err := runCommand(step[0], step[1:]...); err != nil {
			os.Exit(1)
		}
	}

	cmd := exec.Command("govulncheck", "-format=json", "./...")
	
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "❌ govulncheck failed: %v\n%s\n", err, stderr.String())
		os.Exit(1)
	}

	dec := json.NewDecoder(&stdout)
	vulns := make(map[string]string)

	for {
		var wrapper map[string]json.RawMessage
		if err := dec.Decode(&wrapper); err != nil {
			break
		}
	
		if data, ok := wrapper["finding"]; ok {
			var f Finding
			if err := json.Unmarshal(data, &f); err == nil && f.OSV != "" {
				vulns[f.OSV] = f.FixedVersion
			}
		}
	}

	if len(vulns) > 0 {
		fmt.Printf("🚨 %d vulnerabilities found:\n", len(vulns))
		for id, fix := range vulns {
			fmt.Printf("- [%s](https://pkg.go.dev/vuln/%s) — Fixed in: %s\n", id, id, fix)
		}
		os.Exit(1)
	}

	fmt.Println("✅ No vulnerabilities found!")
}

func runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	fmt.Printf("$ %s %s\n%s\n", name, strings.Join(args, " "), string(output))
	if err != nil {
		return fmt.Errorf("command %s failed: %v", name, err)
	}
	return nil
}
