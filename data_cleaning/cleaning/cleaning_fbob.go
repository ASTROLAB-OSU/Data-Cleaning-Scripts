package cleaning

import (
	"fmt"
	"strings"
)

// checkFBOB detects entries that would be removed for having fbobh_ prefix
func CheckFBOB(usernames, passwords []string, removedFBOB *[]string) int {
	count := 0
	for idx, pwd := range passwords {
		if strings.HasPrefix(pwd, "fbobh_") {
			*removedFBOB = append(*removedFBOB, fmt.Sprintf("%s:%s", usernames[idx], pwd))
			count++
		}
	}
	return count
}

// removeFBOB removes entries with fbobh_ prefix
func RemoveFBOB(usernames, passwords []string, removedFBOB *[]string) ([]string, []string) {
	var newUsernames, newPasswords []string
	for idx, pwd := range passwords {
		if strings.HasPrefix(pwd, "fbobh_") {
			*removedFBOB = append(*removedFBOB, fmt.Sprintf("%s:%s", usernames[idx], pwd))
		} else {
			newUsernames = append(newUsernames, usernames[idx])
			newPasswords = append(newPasswords, pwd)
		}
	}
	return newUsernames, newPasswords
}
