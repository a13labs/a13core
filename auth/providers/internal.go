package providers

import (
	"crypto/rand"
	"encoding/base64"

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

func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func VerifyPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}
