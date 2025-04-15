package providers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"golang.org/x/crypto/bcrypt"
)

func GenerateUniqueID() string {
	// Generate a random unique ID
	rawID := make([]byte, 16) // 16 bytes = 128 bits
	_, err := rand.Read(rawID)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(rawID)
}

func GenerateRandomPassword() (string, string, error) {
	// Generate a random password
	rawPassword := make([]byte, 16) // 16 bytes = 128 bits
	_, err := rand.Read(rawPassword)
	if err != nil {
		return "", "", err
	}
	password := base64.RawURLEncoding.EncodeToString(rawPassword)

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}

	return password, string(hashedPassword), nil
}

func HashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}
