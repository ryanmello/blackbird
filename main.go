package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

type Finding struct {
	OSV          string `json:"osv"`
	FixedVersion string `json:"fixed_version"`
}

type VulnCheckOutput struct {
	Config struct {
		ProtocolVersion string `json:"protocol_version"`
		ScannerName     string `json:"scanner_name"`
		ScannerVersion  string `json:"scanner_version"`
		DB              string `json:"db"`
		GoVersion       string `json:"go_version"`
		ScanLevel       string `json:"scan_level"`
		ScanMode        string `json:"scan_mode"`
	} `json:"config"`
	Findings []struct {
		OSV          string `json:"osv"`
		FixedVersion string `json:"fixed_version"`
		Trace        []struct {
			Module   string `json:"module"`
			Version  string `json:"version"`
			Package  string `json:"package"`
			Function string `json:"function"`
			Position struct {
				Filename string `json:"filename"`
				Line     int    `json:"line"`
				Column   int    `json:"column"`
			} `json:"position"`
		} `json:"trace"`
	} `json:"findings"`
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
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("govulncheck encountered an error: %v\n", err)
		fmt.Printf("Stderr output: %s\n", stderr.String())
		os.Exit(1)
	}

	// Parse the JSON output
	var output VulnCheckOutput
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		fmt.Printf("Failed to parse govulncheck output: %v\n", err)
		fmt.Printf("Raw output: %s\n", stdout.String())
		os.Exit(1)
	}

	if len(output.Findings) > 0 {
		fmt.Println("🚨 Vulnerabilities found:")
		for _, f := range output.Findings {
			link := fmt.Sprintf("https://pkg.go.dev/vuln/%s", f.OSV)
			fmt.Printf("- [%s](%s) — Fixed in: %s\n", f.OSV, link, f.FixedVersion)
			fmt.Println("  Trace:")
			for _, t := range f.Trace {
				fmt.Printf("  - %s@%s: %s.%s\n", t.Module, t.Version, t.Package, t.Function)
			}
		}
		os.Exit(1)
	} else {
		fmt.Println("✅ No vulnerabilities found!")
	}
}
