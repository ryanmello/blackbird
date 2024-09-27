package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

type Finding struct {
	OSV          string `json:"osv"`
	FixedVersion string `json:"fixed_version"`
}

func main() {
	// Get the workspace directory from command line arguments
	workspaceDir := "/github/workspace"
	if len(os.Args) > 1 {
		workspaceDir = os.Args[1]
	}

	// Change to the workspace directory
	if err := os.Chdir(workspaceDir); err != nil {
		fmt.Printf("Failed to change to workspace directory %s: %v\n", workspaceDir, err)
		os.Exit(1)
	}

	// Run go mod download to ensure all dependencies are available
	modCmd := exec.Command("go", "mod", "download")
	if err := modCmd.Run(); err != nil {
		fmt.Printf("Failed to download dependencies: %v\n", err)
		os.Exit(1)
	}

	// Use the current directory for scanning
	scanPath := "./..."

	// Run govulncheck with verbose output
	cmd := exec.Command("govulncheck", "-format=json", "-v", scanPath)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Println("Failed to get stdout", err)
		return
	}

	if err := cmd.Start(); err != nil {
		fmt.Println("Failed to start govulncheck:", err)
		os.Exit(1)
	}

	scanner := bufio.NewScanner(stdout)
	findings := []Finding{}

	for scanner.Scan() {
		line := scanner.Bytes()

		var obj map[string]any
		if err := json.Unmarshal(line, &obj); err != nil {
			continue
		}

		if findingData, ok := obj["finding"]; ok {
			rawFinding, err := json.Marshal(findingData)
			if err != nil {
				continue
			}

			var finding Finding
			if err := json.Unmarshal(rawFinding, &finding); err != nil {
				continue
			}

			findings = append(findings, finding)
		}
	}

	if err := cmd.Wait(); err != nil {
		fmt.Println("govulncheck encountered an error:", err)
	}

	if len(findings) > 0 {
		fmt.Println("🚨 Vulnerabilities found:")
		for _, f := range findings {
			link := fmt.Sprintf("https://pkg.go.dev/vuln/%s", f.OSV)
			fmt.Printf("- [%s](%s) — Fixed in: %s\n", f.OSV, link, f.FixedVersion)
		}
		os.Exit(1)
	} else {
		fmt.Println("✅ No vulnerabilities found!")
	}
}
