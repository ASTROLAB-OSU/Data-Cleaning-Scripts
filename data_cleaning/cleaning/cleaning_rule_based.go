package cleaning

import (
	"Data-Cleaning/config"
	"fmt"
	"regexp"
	"sort"
	"strconv"
)

// sequentialUsernames maps "base@domain" to sequence information.
var sequentialUsernames = make(map[string]SeqInfo)

// SeqInfo holds tracking info for sequential usernames.
type SeqInfo struct {
	lastNumber   int
	count        int
	startRemoval bool
}

// detectSequentialUsernames detects sequences of 100 or more usernames with an incrementing number suffix
func detectSequentialUsernames(email string, sequentialUsernames map[string]SeqInfo) bool {
	re := regexp.MustCompile(`^([a-zA-Z0-9._%+\-]+?)(\d+)@(.+)$`)
	matches := re.FindStringSubmatch(email)
	if matches == nil || len(matches) < 4 {
		return false
	}

	baseName := matches[1]
	numberStr := matches[2]
	domain := matches[3]
	number, err := strconv.Atoi(numberStr)
	if err != nil {
		return false
	}

	key := fmt.Sprintf("%s@%s", baseName, domain)

	if seq, exists := sequentialUsernames[key]; exists {
		if number == seq.lastNumber+1 {
			seq.count++
			seq.startRemoval = seq.startRemoval || (seq.count >= 100)
			seq.lastNumber = number
			sequentialUsernames[key] = seq
		} else {
			sequentialUsernames[key] = SeqInfo{lastNumber: number, count: 1, startRemoval: false}
		}
	} else {
		sequentialUsernames[key] = SeqInfo{lastNumber: number, count: 1, startRemoval: false}
	}

	return sequentialUsernames[key].startRemoval
}

// identifySequentialUsernames does a first pass to identify all sequential username patterns
func identifySequentialUsernames(usernames []string) map[string]bool {
	sequences := make(map[string]map[int]bool) // maps baseEmail -> set of numbers
	sequentialBases := make(map[string]bool)   // marks which base emails are sequential

	re := regexp.MustCompile(`^([a-zA-Z0-9._%+\-]+?)(\d+)@(.+)$`)

	// First pass: collect all numbers for each base email
	for _, email := range usernames {
		matches := re.FindStringSubmatch(email)
		if matches == nil || len(matches) < 4 {
			continue
		}

		baseName := matches[1]
		numberStr := matches[2]
		domain := matches[3]
		number, err := strconv.Atoi(numberStr)
		if err != nil {
			continue
		}

		key := fmt.Sprintf("%s@%s", baseName, domain)
		if sequences[key] == nil {
			sequences[key] = make(map[int]bool)
		}
		sequences[key][number] = true
	}

	// Second pass: analyze number sequences
	for key, numbers := range sequences {
		// Convert map to sorted slice for analysis
		var sorted []int
		for num := range numbers {
			sorted = append(sorted, num)
		}
		sort.Ints(sorted)

		// Check for sequences of 100 or more consecutive numbers
		consecutive := 1
		for i := 1; i < len(sorted); i++ {
			if sorted[i] == sorted[i-1]+1 {
				consecutive++
				if consecutive >= 100 {
					sequentialBases[key] = true
					break
				}
			} else {
				consecutive = 1
			}
		}
	}

	return sequentialBases
}

// checkRuleBased counts credentials that would be removed by rule-based filters
func CheckRuleBased(usernames, passwords []string, removedRuleBased *[]string, filestats *config.CleaningStats, tldSet map[string]bool) {

	// Track duplicates
	duplicates := make(map[string]int)

	// First pass: identify sequential usernames
	sequentialBases := identifySequentialUsernames(usernames)

	// Process each credential
	for i := range usernames {
		email := usernames[i]
		password := passwords[i]
		credential := fmt.Sprintf("%s:%s", email, password)
		shouldRemove := false

		// Check if this email matches a known sequential pattern
		re := regexp.MustCompile(`^([a-zA-Z0-9._%+\-]+?)(\d+)@(.+)$`)
		if matches := re.FindStringSubmatch(email); matches != nil && len(matches) >= 4 {
			baseEmail := fmt.Sprintf("%s@%s", matches[1], matches[3])
			if sequentialBases[baseEmail] {
				filestats.Rule_SeqUserRemovals++
				shouldRemove = true
			}
		}

		// Check for duplicate credentials
		duplicates[credential]++
		if duplicates[credential] > 1 {
			filestats.Rule_DupeRemovals++
			shouldRemove = true
		}

		// Check email length
		if len(email) < 10 || len(email) > 40 {
			filestats.Rule_LenEmailRemovals++
			shouldRemove = true
		}

		// Validate email TLD
		result, _, _ := IsValidTLD(email, tldSet)
		if !result {
			filestats.Rule_TLDRemovals++
			shouldRemove = true
		}

		if shouldRemove {
			*removedRuleBased = append(*removedRuleBased, credential)
			filestats.RuleBasedRemovals++
		}
	}
}

// removeRuleBased actually removes credentials based on rule-based filters
func RemoveRuleBased(usernames, passwords []string, removedRuleBased *[]string, filestats *config.CleaningStats, tldSet map[string]bool) ([]string, []string) {
	// Prepare output lists
	filteredUsernames := []string{}
	filteredPasswords := []string{}

	// Track duplicates
	duplicates := make(map[string]int)

	// First pass: identify sequential usernames
	sequentialBases := identifySequentialUsernames(usernames)

	// Process each credential
	for i := range usernames {
		email := usernames[i]
		password := passwords[i]
		credential := fmt.Sprintf("%s:%s", email, password)

		// Check if this email matches a known sequential pattern
		re := regexp.MustCompile(`^([a-zA-Z0-9._%+\-]+?)(\d+)@(.+)$`)
		if matches := re.FindStringSubmatch(email); matches != nil && len(matches) >= 4 {
			baseEmail := fmt.Sprintf("%s@%s", matches[1], matches[3])
			if sequentialBases[baseEmail] {
				filestats.Rule_SeqUserRemovals++
				*removedRuleBased = append(*removedRuleBased, credential)
				continue
			}
		}

		// Check for duplicate credentials
		duplicates[credential]++
		if duplicates[credential] > 1 {
			filestats.Rule_DupeRemovals++
			*removedRuleBased = append(*removedRuleBased, credential)
			continue
		}

		// Check email length
		if len(email) < 10 || len(email) > 40 {
			filestats.Rule_LenEmailRemovals++
			*removedRuleBased = append(*removedRuleBased, credential)
			continue
		}

		// Validate email TLD
		result, _, _ := IsValidTLD(email, tldSet)
		if !result {
			filestats.Rule_TLDRemovals++
			*removedRuleBased = append(*removedRuleBased, credential)
			continue
		}

		// If all checks pass, add to filtered lists
		filteredUsernames = append(filteredUsernames, email)
		filteredPasswords = append(filteredPasswords, password)
	}

	return filteredUsernames, filteredPasswords
}
