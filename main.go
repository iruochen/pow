package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// findProofOfWork to find a nonce such that the SHA256 hash of (nickname + nonce) starts with targetZeros number of '0's
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

// generateKeyPair generates an RSA key pair of the specified size in bits
func generateKeyPair(sizyBits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, sizyBits)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating RSA key: %v", err)
	}
	publicKey := &privateKey.PublicKey
	return privateKey, publicKey, nil
}

// signData signs the data using the provided RSA private key and returns the signature
func signData(privateKey *rsa.PrivateKey, data []byte) ([]byte, error) {
	hashed := sha256.Sum256(data)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, 0, hashed[:])
	if err != nil {
		return nil, fmt.Errorf("error signing data: %v", err)
	}
	return signature, nil
}

// verifySignature verifies the signature of the data using the provided RSA public key
func verifySignature(publicKey *rsa.PublicKey, data []byte, signature []byte) error {
	hashed := sha256.Sum256(data)
	err := rsa.VerifyPKCS1v15(publicKey, 0, hashed[:], signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %v", err)
	}
	return nil
}

func main() {
	fmt.Println("Generating RSA Key Pair...")
	privateKey, publicKey, err := generateKeyPair(2048)
	if err != nil {
		fmt.Println("Key generation error:", err)
		return
	}
	fmt.Println("RSA Key Pair generated.")
	fmt.Println("Public Key Modulus:", publicKey.N.BitLen())

	fmt.Println("execute Proof of Work...")
	nickname := "ruochen"
	target_zeros := 4
	fmt.Println("prefix with ", target_zeros, " zeros")
	timeSpent, content, nonce, hashedValue := findProofOfWork(nickname, target_zeros)
	fmt.Printf("Time taken: %s\n", timeSpent)
	fmt.Printf("Content: %s\n", content)
	fmt.Printf("Nonce: %d\n", nonce)
	fmt.Printf("prefix: %s\n", hashedValue[:target_zeros])
	fmt.Printf("SHA256 Hash: %s\n", hashedValue)
	powDataBytes := []byte(content)

	fmt.Println("Signing the Proof of Work data...")
	signature, err := signData(privateKey, powDataBytes)
	if err != nil {
		fmt.Println("Signing error:", err)
		return
	}
	fmt.Println("Data signed.")
	fmt.Printf("Signature: %x\n", signature)

	fmt.Println("Verifying the signature...")
	err = verifySignature(publicKey, powDataBytes, signature)
	if err != nil {
		fmt.Println("Verification error:", err)
		return
	}
	fmt.Println("Signature verified successfully.")
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
