package cleaning

import (
	"Data-Cleaning/config"
	"net/mail"
	"regexp"
	"strings"
)

// allowedControlChars: only tab (9), newline (10), and carriage return (13) are allowed below 32.
var allowedControlChars = map[rune]bool{9: true, 10: true, 13: true}

func isASCII(s string) bool {
	r := []rune(s)
	seen_control := false // once you see a 'controlChar', the remaining chars should also be 'controlChar's
	for i := 0; i < len(r); i++ {
		// ASCII range check
		if (r[i] <= 126 && r[i] > 31) && seen_control == false {
			continue
		} else if allowedControlChars[r[i]] { // \n, \t, and/or \r are only allowed at end of cred
			seen_control = true
			continue
		} else {
			return false
		}
	}
	return true
}

// priorWorkChecks performs various checks on a credential line and returns true if the credential passes.
func priorWorkChecks(credential, email, password string, removedPriorWorks *[]string, emailDuplicates map[string]int, excessiveEmails map[string]bool, filestats *config.CleaningStats) bool {
	shouldRemove := false

	// Check for non-ascii characters outside allowed control chars.
	if !isASCII(credential) {
		filestats.Prior_AsciiRemovals++
		shouldRemove = true
	}
	// Check password length constraints.
	if len(password) < 4 || len(password) > 29 {
		filestats.Prior_LenRemovals++
		shouldRemove = true
	}
	// Check if password has 20 hex substring
	hexRe := regexp.MustCompile(`[0-9a-fA-F]{20}`)
	if hexRe.MatchString(password) {
		filestats.Prior_HexRemovals++
		shouldRemove = true
	}
	// Validate email format
	_, err := mail.ParseAddress(email)
	if err != nil {
		filestats.Prior_InvEmailRemovals++
		shouldRemove = true
	}

	// Check if the email is already known to be excessive
	if excessiveEmails[email] {
		filestats.Prior_ExcEmailRemovals++
		shouldRemove = true
	}

	if shouldRemove {
		*removedPriorWorks = append(*removedPriorWorks, credential)
		return false
	}

	return true
}

// counts email occurances then processes priorworkchecks
func PriorWorksCleaning(originalUsernames []string, originalPasswords []string, emailLimit int, removedPriorWorks *[]string, filestats *config.CleaningStats, dryrun bool) ([]string, []string) {
	var usernames []string
	var passwords []string
	// First pass: count all email occurrences
	emailCounts := make(map[string]int)
	excessiveEmails := make(map[string]bool)

	for _, user := range originalUsernames {
		email := strings.ToLower(user)
		emailCounts[email]++
		if emailCounts[email] > emailLimit {
			excessiveEmails[email] = true
		}
	}

	// Second pass: process entries with prior work checks
	for i := range originalUsernames {
		user := originalUsernames[i]
		pass := originalPasswords[i]
		username := strings.ToLower(user)
		line := user + ":" + pass

		// Perform all checks
		if dryrun {
			// In dry-run, add everything to usernames/passwords (no actual removal)
			usernames = append(usernames, user)
			passwords = append(passwords, pass)
			// But still track what WOULD be removed
			_ = priorWorkChecks(line, username, pass, removedPriorWorks, emailCounts, excessiveEmails, filestats)
		} else {
			// In normal mode, only add if it passes checks
			if priorWorkChecks(line, username, pass, removedPriorWorks, emailCounts, excessiveEmails, filestats) {
				usernames = append(usernames, user)
				passwords = append(passwords, pass)
			}
		}
	}

	return usernames, passwords
}
