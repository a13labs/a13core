package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func CreateJWTToken(subject, audience string) (string, error) {

	expirationTime := (time.Now().Add(time.Hour * time.Duration(authConfig.ExpirationTime))).Unix()

	// Define the claims
	claims := jwt.MapClaims{
		"sub": subject,           // Subject or user ID
		"exp": expirationTime,    // Expiration time
		"iat": time.Now().Unix(), // Issued at time
		"aud": audience,          // Audience
	}

	// Create a new token using the HS256 signing method
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with your secret key
	tokenString, err := token.SignedString([]byte(authConfig.SecretKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func VerifyJWTToken(tokenString, subject, audience string) bool {

	// Parse the token
	_, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(authConfig.SecretKey), nil
	},
		jwt.WithExpirationRequired(),
		jwt.WithAudience(audience),
		jwt.WithSubject(subject))

	// Handle errors
	if err != nil {
		return false
	}

	return true
}
