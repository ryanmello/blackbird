package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	// Define command line flags
	dir := flag.String("dir", ".", "Directory to check for Go files")
	flag.Parse()

	// Find all Go files in the specified directory
	var goFiles []string
	err := filepath.Walk(*dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".go") {
			goFiles = append(goFiles, path)
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Error walking directory: %v\n", err)
		os.Exit(1)
	}

	if len(goFiles) == 0 {
		fmt.Printf("No Go files found in directory: %s\n", *dir)
		os.Exit(0)
	}

	// Run go vet on all found Go files
	cmd := exec.Command("go", "vet", "./...")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Println("❌ Go vet found issues in the code")
		os.Exit(1)
	}

	fmt.Println("✅ All Go files passed vet check")
}
