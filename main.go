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

func runCommand(name string, arg ...string) error {
	cmd := exec.Command(name, arg...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command %s failed: %v\nOutput: %s", name, err, string(output))
	}
	fmt.Printf("Command %s output:\n%s\n", name, string(output))
	return nil
}

func main() {
	// Get the workspace directory from command line arguments
	workspaceDir := "/github/workspace"
	if len(os.Args) > 1 {
		workspaceDir = os.Args[1]
	}

	// Print current directory and its contents
	if dir, err := os.Getwd(); err == nil {
		fmt.Printf("Current directory: %s\n", dir)
	}
	if files, err := os.ReadDir("."); err == nil {
		fmt.Println("Directory contents:")
		for _, file := range files {
			fmt.Printf("- %s\n", file.Name())
		}
	}

	// Change to the workspace directory
	if err := os.Chdir(workspaceDir); err != nil {
		fmt.Printf("Failed to change to workspace directory %s: %v\n", workspaceDir, err)
		os.Exit(1)
	}

	// Print Go version
	if err := runCommand("go", "version"); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Print all dependencies
	if err := runCommand("go", "list", "-m", "all"); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Run go mod download to ensure all dependencies are available
	if err := runCommand("go", "mod", "download"); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Use the current directory for scanning
	scanPath := "./..."

	// Run govulncheck
	cmd := exec.Command("govulncheck", "-format=json", scanPath)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Println("Failed to get stdout:", err)
		return
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		fmt.Println("Failed to get stderr:", err)
		return
	}

	if err := cmd.Start(); err != nil {
		fmt.Println("Failed to start govulncheck:", err)
		os.Exit(1)
	}

	// Read stderr in a separate goroutine
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			fmt.Println("govulncheck stderr:", scanner.Text())
		}
	}()

	scanner := bufio.NewScanner(stdout)
	findings := []Finding{}

	for scanner.Scan() {
		line := scanner.Bytes()
		fmt.Printf("Raw govulncheck output: %s\n", string(line))

		var obj map[string]any
		if err := json.Unmarshal(line, &obj); err != nil {
			fmt.Printf("Failed to unmarshal JSON: %v\n", err)
			continue
		}

		if findingData, ok := obj["finding"]; ok {
			rawFinding, err := json.Marshal(findingData)
			if err != nil {
				fmt.Printf("Failed to marshal finding: %v\n", err)
				continue
			}

			var finding Finding
			if err := json.Unmarshal(rawFinding, &finding); err != nil {
				fmt.Printf("Failed to unmarshal finding: %v\n", err)
				continue
			}

			findings = append(findings, finding)
		}
	}

	if err := cmd.Wait(); err != nil {
		fmt.Println("govulncheck encountered an error:", err)
		os.Exit(1)
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
