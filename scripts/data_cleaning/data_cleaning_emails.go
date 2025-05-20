package main

import (
	"fmt"
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

// allEqual returns true if all strings in the slice are identical.
func allEqual(slice []string) bool {
	if len(slice) == 0 {
		return true
	}
	first := slice[0]
	for _, s := range slice {
		if s != first {
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

// removeSuspiciousEmails processes credentials and removes blocks of emails
// based on suspicious sequences. Removed credentials are recorded in removedSuspiciousEmail
// in the format "username:password". It returns new slices of usernames and passwords.
func removeSuspiciousEmails(usernames, passwords []string, removedSuspiciousEmail *[]string) ([]string, []string) {
	// Suspicious sequences to check against.
	suspiciousSequences := [][]string{
		{"@epost.de", "@gmx.de", "@lycos.de", "@web.de", "@yahoo.de"},
		{"@inbox.ru", "@list.ru", "@mail.ru", "@rambler.ru", "@yandex.ru"},
		{"@bk.ru", "@gmail.com", "@gmx.com", "@inbox.ru", "@list.ru", "@mail.ru"},
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

		processed := false
		// Try each suspicious sequence candidate.
		for _, seq := range suspiciousSequences {
			L := len(seq)
			// Case 1: Block length exactly equals L.
			if len(blockIndices) == L {
				var blockDomains []string
				for _, k := range blockIndices {
					blockDomains = append(blockDomains, getDomain(usernames[k]))
				}
				if slicesEqual(blockDomains, seq) {
					var blockPasswords []string
					for _, k := range blockIndices {
						blockPasswords = append(blockPasswords, passwords[k])
					}
					if allEqual(blockPasswords) {
						// Remove the entire block.
						for _, k := range blockIndices {
							*removedSuspiciousEmail = append(*removedSuspiciousEmail, fmt.Sprintf("%s:%s", usernames[k], passwords[k]))
						}
						processed = true
						break
					}
				}
			} else if len(blockIndices) == L+1 {
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
						var suspiciousPasswords []string
						for _, k := range suspiciousIdx {
							suspiciousPasswords = append(suspiciousPasswords, passwords[k])
						}
						if allEqual(suspiciousPasswords) {
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

	return newUsernames, newPasswords
}
