package auth

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestCreateJWTToken(t *testing.T) {
	// Mock configuration
	authConfig = AuthConfig{
		SecretKey:      "test_secret_key",
		ExpirationTime: 1, // 1 hour
	}

	subject := "test_user"
	audience := "test_audience"

	token, err := CreateJWTToken(subject, audience)
	if err != nil {
		t.Fatalf("Failed to create JWT token: %v", err)
	}

	if token == "" {
		t.Error("Expected a non-empty token string")
	}

	// Parse the token to verify claims
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(authConfig.SecretKey), nil
	})
	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok || !parsedToken.Valid {
		t.Fatal("Failed to parse claims or token is invalid")
	}

	if claims["sub"] != subject {
		t.Errorf("Expected subject %s, got %s", subject, claims["sub"])
	}

	if claims["aud"] != audience {
		t.Errorf("Expected audience %s, got %s", audience, claims["aud"])
	}
}

func TestVerifyJWTToken(t *testing.T) {
	// Mock configuration
	authConfig = AuthConfig{
		SecretKey:      "test_secret_key",
		ExpirationTime: 1, // 1 hour
	}

	subject := "test_user"
	audience := "test_audience"

	// Create a valid token
	token, err := CreateJWTToken(subject, audience)
	if err != nil {
		t.Fatalf("Failed to create JWT token: %v", err)
	}

	// Verify the token
	if !VerifyJWTToken(token, subject, audience) {
		t.Error("Expected token to be valid, but it was not")
	}

	// Test with an invalid token
	invalidToken := token + "invalid"
	if VerifyJWTToken(invalidToken, subject, audience) {
		t.Error("Expected token to be invalid, but it was valid")
	}

	// Test with an expired token
	authConfig.ExpirationTime = -1 // Set expiration time to the past
	expiredToken, err := CreateJWTToken(subject, audience)
	if err != nil {
		t.Fatalf("Failed to create expired JWT token: %v", err)
	}

	if VerifyJWTToken(expiredToken, subject, audience) {
		t.Error("Expected token to be invalid due to expiration, but it was valid")
	}

	if VerifyJWTToken(token, "wrong_subject", audience) {
		t.Error("Expected token to be invalid due to wrong subject, but it was valid")
	}

	if VerifyJWTToken(token, subject, "wrong_audience") {
		t.Error("Expected token to be invalid due to wrong audience, but it was valid")
	}
}
