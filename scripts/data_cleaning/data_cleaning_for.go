package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// removeSuspiciousFollowOnRatios processes the credentials and removes those
// with suspicious follow-on ratios. For each removed credential, the username and password
// are recorded in "[email:password]" format in removedFor.
// It returns new slices for usernames and passwords. If an error occurs during processing,
// it is returned.
func removeSuspiciousFollowOnRatios(usernames, passwords []string, removedFor *[]string) ([]string, []string, error) {
	// If no passwords, nothing to process.
	if len(passwords) == 0 {
		return usernames, passwords, nil
	}

	// Load the pre-computed suspicious passwords list
	file, err := os.Open("./for_passwords_identified.json")
	if err != nil {
		return nil, nil, fmt.Errorf("error opening suspicious passwords file: %v", err)
	}
	defer file.Close()

	var suspiciousPasswordsList []string
	if err := json.NewDecoder(file).Decode(&suspiciousPasswordsList); err != nil {
		return nil, nil, fmt.Errorf("error decoding suspicious passwords: %v", err)
	}

	// Convert to map for faster lookups
	suspiciousPasswords := make(map[string]bool)
	for _, pwd := range suspiciousPasswordsList {
		suspiciousPasswords[pwd] = true
	}

	// Process each credential
	var newUsernames, newPasswords []string
	for idx, pwd := range passwords {
		if suspiciousPasswords[pwd] {
			// This password is on the suspicious list
			*removedFor = append(*removedFor, fmt.Sprintf("%s:%s", usernames[idx], pwd))
		} else {
			// Keep this credential
			newUsernames = append(newUsernames, usernames[idx])
			newPasswords = append(newPasswords, pwd)
		}
	}

	return newUsernames, newPasswords, nil
}
