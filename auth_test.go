package main

import (
	"os"
	"testing"
)

func createTestUserStore(t *testing.T) *UserStore {
	tmpDir, err := os.MkdirTemp("", "auth-test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	store, err := NewUserStore("test-encryption-key-32-bytes!!", tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestNewAuthService(t *testing.T) {
	userStore := createTestUserStore(t)
	authService := NewAuthService(userStore, "test-jwt-secret")

	if authService == nil {
		t.Fatal("NewAuthService should not return nil")
	}

	if authService.userStore != userStore {
		t.Error("userStore not set correctly")
	}

	if authService.jwtSecret != "test-jwt-secret" {
		t.Error("jwtSecret not set correctly")
	}
}

func TestGenerateIDToken(t *testing.T) {
	userStore := createTestUserStore(t)
	authService := NewAuthService(userStore, "test-jwt-secret")

	user := &User{
		ID:            "user-123",
		Username:      "testuser",
		Email:         "test@example.com",
		EmailVerified: true,
		Roles:         []string{"user", "admin"},
	}

	token, err := authService.GenerateIDToken(user)
	if err != nil {
		t.Fatalf("GenerateIDToken failed: %v", err)
	}

	if token == "" {
		t.Error("token should not be empty")
	}

	// Validate the token
	claims, err := authService.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	if claims.Sub != user.ID {
		t.Errorf("expected sub %s, got %s", user.ID, claims.Sub)
	}

	if claims.Email != user.Email {
		t.Errorf("expected email %s, got %s", user.Email, claims.Email)
	}

	if claims.EmailVerified != user.EmailVerified {
		t.Errorf("expected email_verified %v, got %v", user.EmailVerified, claims.EmailVerified)
	}
}

func TestGenerateAccessToken(t *testing.T) {
	userStore := createTestUserStore(t)
	authService := NewAuthService(userStore, "test-jwt-secret")

	user := &User{
		ID:    "user-456",
		Roles: []string{"user"},
	}

	token, err := authService.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	if token == "" {
		t.Error("token should not be empty")
	}

	// Validate the token
	claims, err := authService.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}

	if claims.Sub != user.ID {
		t.Errorf("expected sub %s, got %s", user.ID, claims.Sub)
	}
}

func TestValidateToken_InvalidToken(t *testing.T) {
	userStore := createTestUserStore(t)
	authService := NewAuthService(userStore, "test-jwt-secret")

	_, err := authService.ValidateToken("invalid-token")
	if err == nil {
		t.Error("ValidateToken should fail with invalid token")
	}
}

func TestValidateToken_WrongSecret(t *testing.T) {
	userStore := createTestUserStore(t)
	authService1 := NewAuthService(userStore, "secret-1")
	authService2 := NewAuthService(userStore, "secret-2")

	user := &User{
		ID:    "user-789",
		Roles: []string{"user"},
	}

	token, err := authService1.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	// Token generated with secret-1 should not validate with secret-2
	_, err = authService2.ValidateToken(token)
	if err == nil {
		t.Error("ValidateToken should fail with wrong secret")
	}
}

func TestAuthenticate(t *testing.T) {
	userStore := createTestUserStore(t)
	authService := NewAuthService(userStore, "test-jwt-secret")

	// Create a user first
	_, err := userStore.CreateUser("authuser", "auth@example.com", "password123")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Test successful authentication
	user, err := authService.Authenticate("authuser", "password123")
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	if user.Username != "authuser" {
		t.Errorf("expected username authuser, got %s", user.Username)
	}

	// Test failed authentication with wrong password
	_, err = authService.Authenticate("authuser", "wrongpassword")
	if err == nil {
		t.Error("Authenticate should fail with wrong password")
	}

	// Test failed authentication with non-existent user
	_, err = authService.Authenticate("nonexistent", "password123")
	if err == nil {
		t.Error("Authenticate should fail with non-existent user")
	}
}
