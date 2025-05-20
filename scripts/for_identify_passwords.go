package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// PrefixRecord represents one record from the prefix statistics JSON.
type PrefixRecord struct {
	Prefix          string  `json:"prefix"`
	StandaloneCount float64 `json:"standalone_count"`
	FollowingCount  float64 `json:"following_count"`
}

// calcCurve computes the threshold for a given standalone count
// and returns true if the followup count is less than the threshold.
func calcCurve(standalone, followup float64) bool {
	var threshold float64
	switch {
	case standalone >= 3000 && standalone <= 5000:
		threshold = 1
	case standalone > 5000 && standalone <= 20000:
		threshold = (standalone / 500) - 10
	case standalone > 20000:
		threshold = (standalone / 120) - 135
	default:
		return false
	}
	return followup < threshold
}

// identifySuspiciousPasswords processes the prefix statistics and identifies passwords
// with suspicious follow-on ratios.
func identifySuspiciousPasswords() (map[string]bool, error) {
	// Open and load JSON data
	file, err := os.Open("./data_cleaning/prefix_statistics.json")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var allStats map[string][]PrefixRecord
	if err := json.NewDecoder(file).Decode(&allStats); err != nil {
		return nil, err
	}

	// Collect all prefix records
	var prefixRecords []PrefixRecord
	for _, stats := range allStats {
		prefixRecords = append(prefixRecords, stats...)
	}

	// Identify suspicious passwords
	suspiciousPasswords := make(map[string]bool)
	for _, record := range prefixRecords {
		if calcCurve(record.StandaloneCount, record.FollowingCount) {
			suspiciousPasswords[record.Prefix] = true
		}
	}

	return suspiciousPasswords, nil
}

func main() {
	// Identify suspicious passwords
	suspiciousPasswords, err := identifySuspiciousPasswords()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error identifying suspicious passwords: %v\n", err)
		os.Exit(1)
	}

	// Convert map to slice for JSON output
	var passwordsList []string
	for pwd := range suspiciousPasswords {
		passwordsList = append(passwordsList, pwd)
	}

	// Write suspicious passwords to output file
	outputFile, err := os.Create("./data_cleaning/for_passwords_identified.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer outputFile.Close()

	encoder := json.NewEncoder(outputFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(passwordsList); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Found %d suspicious passwords. Results written to for_passwords_identified.json\n", len(passwordsList))
}
