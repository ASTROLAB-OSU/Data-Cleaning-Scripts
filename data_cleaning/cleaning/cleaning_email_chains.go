package cleaning

import (
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"strings"
)

// getLocal returns the part of the email before the "@".
func getLocal(email string) string {
	if at := strings.Index(email, "@"); at != -1 {
		return email[:at]
	}
	return email
}

// getDomain returns the part of the email starting from the "@".
func getDomain(email string) string {
	if at := strings.Index(email, "@"); at != -1 {
		return email[at:]
	}
	return ""
}

// slicesEqual returns true if two string slices are exactly equal.
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, s := range a {
		if s != b[i] {
			return false
		}
	}
	return true
}

// contains checks if a string is in the slice.
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// containsInt checks if an int is in the slice.
func containsInt(slice []int, item int) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// loadSuspiciousChains reads the suspicious_chains.csv file and returns
// a slice of domain chains sorted by length (longest first).
func loadSuspiciousChains(filepath string) ([][]string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open chains file: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	// Allow variable number of fields per record
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("failed to read chains file: %w", err)
	}

	var chains [][]string
	for _, record := range records {
		var chain []string
		for _, domain := range record {
			domain = strings.TrimSpace(domain)
			if domain != "" {
				// Add @ prefix if not already present
				if !strings.HasPrefix(domain, "@") {
					domain = "@" + domain
				}
				chain = append(chain, domain)
			}
		}
		if len(chain) > 0 {
			chains = append(chains, chain)
		}
	}

	// the longest possible chain before matching shorter sub-chains
	sort.Slice(chains, func(i, j int) bool {
		return len(chains[i]) > len(chains[j])
	})

	return chains, nil
}

// RemoveSuspiciousEmails processes credentials and removes blocks of emails
// based on suspicious sequences loaded from CSV. Removed credentials are recorded in
// removedSuspiciousEmail in the format "username:password". It returns new slices of
// usernames and passwords.
func RemoveSuspiciousEmails(usernames, passwords []string, removedSuspiciousEmail *[]string, chainsFilepath string) ([]string, []string, error) {
	// Load suspicious sequences from CSV file (sorted by length, longest first)
	suspiciousSequences, err := loadSuspiciousChains(chainsFilepath)
	if err != nil {
		return nil, nil, err
	}

	if len(suspiciousSequences) == 0 {
		// No suspicious chains found, return original data
		return usernames, passwords, nil
	}

	var newUsernames []string
	var newPasswords []string
	n := len(usernames)

	// Determine the maximum block size: max(L+1) over all suspicious sequences.
	maxBlockSize := 0
	for _, seq := range suspiciousSequences {
		if len(seq)+1 > maxBlockSize {
			maxBlockSize = len(seq) + 1
		}
	}

	// Optimization: Create a map for quick length-based chain lookup
	// Since chains are already sorted by length (longest first), we maintain that order
	chainsByLength := make(map[int][][]string)
	for _, seq := range suspiciousSequences {
		L := len(seq)
		chainsByLength[L] = append(chainsByLength[L], seq)
		chainsByLength[L+1] = append(chainsByLength[L+1], seq)
	}

	i := 0
	for i < n {
		local := getLocal(usernames[i])
		var blockIndices []int
		j := i
		// Group contiguous emails with the same local part (up to maxBlockSize).
		for j < n && getLocal(usernames[j]) == local && len(blockIndices) < maxBlockSize {
			blockIndices = append(blockIndices, j)
			j++
		}

		blockLen := len(blockIndices)
		processed := false

		// Get candidate chains for this block length
		candidateChains, exists := chainsByLength[blockLen]
		if !exists {
			// No chains match this block length, keep the block unchanged
			for _, k := range blockIndices {
				newUsernames = append(newUsernames, usernames[k])
				newPasswords = append(newPasswords, passwords[k])
			}
			i = j
			continue
		}

		// Try each suspicious sequence candidate that matches the block length.
		for _, seq := range candidateChains {
			L := len(seq)
			if blockLen == L {
				var blockDomains []string
				for _, k := range blockIndices {
					blockDomains = append(blockDomains, getDomain(usernames[k]))
				}
				if slicesEqual(blockDomains, seq) {
					// Optimization: Early check - verify passwords match before allocating slice
					firstPass := passwords[blockIndices[0]]
					allMatch := true
					for _, k := range blockIndices {
						if passwords[k] != firstPass {
							allMatch = false
							break
						}
					}
					if allMatch {
						// Remove the entire block.
						for _, k := range blockIndices {
							*removedSuspiciousEmail = append(*removedSuspiciousEmail, fmt.Sprintf("%s:%s", usernames[k], passwords[k]))
						}
						processed = true
						break
					}
				}
			} else if blockLen == L+1 {
				// Case 2: Block length equals L+1.
				var suspiciousIdx []int
				// Identify indices where the domain is in the candidate sequence.
				for _, k := range blockIndices {
					domain := getDomain(usernames[k])
					if contains(seq, domain) {
						suspiciousIdx = append(suspiciousIdx, k)
					}
				}
				if len(suspiciousIdx) == L {
					var suspiciousBlockDomains []string
					for _, k := range suspiciousIdx {
						suspiciousBlockDomains = append(suspiciousBlockDomains, getDomain(usernames[k]))
					}
					if slicesEqual(suspiciousBlockDomains, seq) {
						// Optimization: Early check - verify passwords match before processing
						firstPass := passwords[suspiciousIdx[0]]
						allMatch := true
						for _, k := range suspiciousIdx {
							if passwords[k] != firstPass {
								allMatch = false
								break
							}
						}
						if allMatch {
							// Remove the suspicious emails.
							for _, k := range suspiciousIdx {
								*removedSuspiciousEmail = append(*removedSuspiciousEmail, fmt.Sprintf("%s:%s", usernames[k], passwords[k]))
							}
							// Keep the non-suspicious email(s).
							for _, k := range blockIndices {
								if !containsInt(suspiciousIdx, k) {
									newUsernames = append(newUsernames, usernames[k])
									newPasswords = append(newPasswords, passwords[k])
								}
							}
							processed = true
							break
						}
					}
				}
			}
		}
		if processed {
			i = j // Skip the entire block.
			continue
		} else {
			// If none of the suspicious sequences matched, keep the block unchanged.
			for _, k := range blockIndices {
				newUsernames = append(newUsernames, usernames[k])
				newPasswords = append(newPasswords, passwords[k])
			}
			i = j
		}
	}

	return newUsernames, newPasswords, nil
}
