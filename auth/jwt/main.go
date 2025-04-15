package jwt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func Create(userID, role string, expire int, secret string) (string, error) {
	// Define token expiration time
	var expirationTime int64
	if expire == 0 {
		expirationTime = 0
	} else {
		expirationTime = (time.Now().Add(time.Hour * time.Duration(expire))).Unix()
	}

	// Define the claims
	claims := jwt.MapClaims{
		"sub":  userID,            // Subject or user ID
		"exp":  expirationTime,    // Expiration time
		"iat":  time.Now().Unix(), // Issued at time
		"role": role,              // Custom claim (e.g., user role)
	}

	// Create a new token using the HS256 signing method
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with your secret key
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func Unmap(tokenString string, secret string) (jwt.MapClaims, error) {
	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return []byte(secret), nil
	})

	// Handle errors
	if err != nil {
		return nil, err
	}

	// Extract claims if the token is valid
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, fmt.Errorf("invalid token")
	}
}
