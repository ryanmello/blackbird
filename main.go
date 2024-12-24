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

type OSV struct {
	ID       string `json:"id"`
	Summary  string `json:"summary"`
	Details  string `json:"details"`
	Affected []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
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

	// Run govulncheck with -mode=binary to scan all dependencies
	cmd := exec.Command("govulncheck", "-format=json", "./...")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("govulncheck encountered an error: %v\n", err)
		fmt.Printf("Stderr output: %s\n", stderr.String())
		os.Exit(1)
	}

	// Split the output into individual JSON objects
	output := stdout.String()
	objects := strings.Split(output, "\n}\n{")

	// Process each JSON object
	vulnerabilities := make(map[string]string)
	for i, obj := range objects {
		// Fix the JSON formatting
		if i == 0 {
			obj = obj + "}"
		} else if i == len(objects)-1 {
			obj = "{" + obj
		} else {
			obj = "{" + obj + "}"
		}

		// Try to parse as OSV
		var osv OSV
		if err := json.Unmarshal([]byte(obj), &osv); err == nil && osv.ID != "" {
			// Extract the fixed version from the first affected range
			if len(osv.Affected) > 0 && len(osv.Affected[0].Ranges) > 0 {
				for _, event := range osv.Affected[0].Ranges[0].Events {
					if event.Fixed != "" {
						vulnerabilities[osv.ID] = event.Fixed
						break
					}
				}
			}
		}
	}

	if len(vulnerabilities) > 0 {
		fmt.Println("🚨 Vulnerabilities found:")
		for id, fixedVersion := range vulnerabilities {
			link := fmt.Sprintf("https://pkg.go.dev/vuln/%s", id)
			fmt.Printf("- [%s](%s) — Fixed in: %s\n", id, link, fixedVersion)
		}
		os.Exit(1)
	} else {
		fmt.Println("✅ No vulnerabilities found!")
	}
}
