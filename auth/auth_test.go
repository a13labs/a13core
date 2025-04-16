package auth

import (
	"encoding/json"
	"testing"

	"github.com/a13labs/a13core/auth/providers"
)

func setupMemoryProvider() {
	providerSettings := `{"users": []}`
	providers.InitializeAuthProvider("memory", json.RawMessage(providerSettings))
}

func TestInitializeAuth(t *testing.T) {
	setupMemoryProvider()

	data := json.RawMessage(`{
		"provider": "memory",
		"secret_key": "test_secret",
		"expiration_time": 48,
		"settings": {}
	}`)

	err := InitializeAuth(data)
	if err != nil {
		t.Fatalf("Failed to initialize auth: %v", err)
	}

	if authConfig.Provider != "memory" {
		t.Errorf("Expected provider to be 'memory', got '%s'", authConfig.Provider)
	}

	if authConfig.SecretKey != "test_secret" {
		t.Errorf("Expected secret key to be 'test_secret', got '%s'", authConfig.SecretKey)
	}

	if authConfig.ExpirationTime != 48 {
		t.Errorf("Expected expiration time to be 48, got %d", authConfig.ExpirationTime)
	}
}

func TestAddUser(t *testing.T) {
	setupMemoryProvider()

	err := AddUser("testuser", "password123", "user")
	if err != nil {
		t.Fatalf("Failed to add user: %v", err)
	}

	users, err := GetUsers()
	if err != nil {
		t.Fatalf("Failed to get users: %v", err)
	}

	if len(users) != 1 || users[0] != "testuser" {
		t.Errorf("Expected user 'testuser' to be added, got %v", users)
	}
}

func TestCheckCredentials(t *testing.T) {
	setupMemoryProvider()

	err := AddUser("testuser", "password123", "user")
	if err != nil {
		t.Fatalf("Failed to add user: %v", err)
	}

	if !CheckCredentials("testuser", "password123") {
		t.Errorf("Expected credentials to be valid")
	}

	if CheckCredentials("testuser", "wrongpassword") {
		t.Errorf("Expected credentials to be invalid")
	}
}

func TestRemoveUser(t *testing.T) {
	setupMemoryProvider()

	err := AddUser("testuser", "password123", "user")
	if err != nil {
		t.Fatalf("Failed to add user: %v", err)
	}

	err = RemoveUser("testuser")
	if err != nil {
		t.Fatalf("Failed to remove user: %v", err)
	}

	users, err := GetUsers()
	if err != nil {
		t.Fatalf("Failed to get users: %v", err)
	}

	if len(users) != 0 {
		t.Errorf("Expected no users, got %v", users)
	}
}

func TestChangePassword(t *testing.T) {
	setupMemoryProvider()

	err := AddUser("testuser", "password123", "user")
	if err != nil {
		t.Fatalf("Failed to add user: %v", err)
	}

	err = ChangePassword("testuser", "newpassword")
	if err != nil {
		t.Fatalf("Failed to change password: %v", err)
	}

	if !CheckCredentials("testuser", "newpassword") {
		t.Errorf("Expected new password to be valid")
	}
}

func TestSetRole(t *testing.T) {
	setupMemoryProvider()

	err := AddUser("testuser", "password123", "user")
	if err != nil {
		t.Fatalf("Failed to add user: %v", err)
	}

	err = SetRole("testuser", "admin")
	if err != nil {
		t.Fatalf("Failed to set role: %v", err)
	}

	role, err := GetRole("testuser")
	if err != nil {
		t.Fatalf("Failed to get role: %v", err)
	}

	if role != "admin" {
		t.Errorf("Expected role to be 'admin', got '%s'", role)
	}
}

func TestGenerateAppPassword(t *testing.T) {
	setupMemoryProvider()

	err := AddUser("testuser", "password123", "user")
	if err != nil {
		t.Fatalf("Failed to add user: %v", err)
	}

	appPassword, err := GenerateAppPassword("app1", "testuser", "admin", 24)
	if err != nil {
		t.Fatalf("Failed to generate app password: %v", err)
	}

	if appPassword == "" {
		t.Errorf("Expected app password to be generated")
	}
}
