package main

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func findProofOfWork(nickname string, targetZeros int) (time.Duration, string, uint64, string) {
	targetPrefix := strings.Repeat("0", targetZeros)
	startTime := time.Now()
	var nonce uint64 = 0
	for {
		content := nickname + strconv.FormatUint(nonce, 10)
		hashBytes := sha256.Sum256([]byte(content))
		hashedValue := fmt.Sprintf("%x", hashBytes)
		if strings.HasPrefix(hashedValue, targetPrefix) {
			endTime := time.Now()
			timeSpent := endTime.Sub(startTime)
			return timeSpent, content, nonce, hashedValue
		}
		nonce++
	}
}

func main() {
	nickname := "ruochen"
	target_zeros := 4
	fmt.Println("prefix with ", target_zeros, " zeros")
	timeSpent, content, nonce, hashedValue := findProofOfWork(nickname, target_zeros)
	fmt.Printf("Time taken: %s\n", timeSpent)
	fmt.Printf("Content: %s\n", content)
	fmt.Printf("Nonce: %d\n", nonce)
	fmt.Printf("prefix: %s\n", hashedValue[:target_zeros])
	fmt.Printf("SHA256 Hash: %s\n", hashedValue)
	fmt.Println("-----------------------------------")

	target_zeros = 5
	fmt.Println("prefix with ", target_zeros, " zeros")
	timeSpent, content, nonce, hashedValue = findProofOfWork(nickname, target_zeros)
	fmt.Printf("Time taken: %s\n", timeSpent)
	fmt.Printf("Content: %s\n", content)
	fmt.Printf("Nonce: %d\n", nonce)
	fmt.Printf("prefix: %s\n", hashedValue[:target_zeros])
	fmt.Printf("SHA256 Hash: %s\n", hashedValue)
}
