package crypto

import (
	"testing"
)

func TestGenerateKey(t *testing.T) {
	key := GenerateKey("test-passphrase")
	if len(key) != 32 {
		t.Errorf("expected key length 32, got %d", len(key))
	}

	// Same passphrase should generate same key
	key2 := GenerateKey("test-passphrase")
	if string(key) != string(key2) {
		t.Error("same passphrase should generate same key")
	}

	// Different passphrase should generate different key
	key3 := GenerateKey("different-passphrase")
	if string(key) == string(key3) {
		t.Error("different passphrase should generate different key")
	}
}

func TestEncryptDecryptData(t *testing.T) {
	passphrase := "test-passphrase-32-bytes-long!!"
	plaintext := []byte("Hello, World! This is a test message.")

	encrypted, err := EncryptData(plaintext, passphrase)
	if err != nil {
		t.Fatalf("EncryptData failed: %v", err)
	}

	if encrypted == "" {
		t.Error("encrypted data should not be empty")
	}

	decrypted, err := DecryptData(encrypted, passphrase)
	if err != nil {
		t.Fatalf("DecryptData failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted data doesn't match original: got %s, want %s", decrypted, plaintext)
	}
}

func TestDecryptData_WrongPassphrase(t *testing.T) {
	passphrase := "test-passphrase"
	plaintext := []byte("Hello, World!")

	encrypted, err := EncryptData(plaintext, passphrase)
	if err != nil {
		t.Fatalf("EncryptData failed: %v", err)
	}

	_, err = DecryptData(encrypted, "wrong-passphrase")
	if err == nil {
		t.Error("DecryptData should fail with wrong passphrase")
	}
}

func TestDecryptData_InvalidBase64(t *testing.T) {
	_, err := DecryptData("not-valid-base64!!!", "passphrase")
	if err == nil {
		t.Error("DecryptData should fail with invalid base64")
	}
}

func TestDecryptData_TooShort(t *testing.T) {
	_, err := DecryptData("YWJj", "passphrase") // "abc" in base64
	if err == nil {
		t.Error("DecryptData should fail with ciphertext too short")
	}
}

func TestHashPassword(t *testing.T) {
	password := "mySecurePassword123"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if hash == "" {
		t.Error("hash should not be empty")
	}

	if hash == password {
		t.Error("hash should not equal password")
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "mySecurePassword123"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if !CheckPasswordHash(password, hash) {
		t.Error("CheckPasswordHash should return true for correct password")
	}

	if CheckPasswordHash("wrongPassword", hash) {
		t.Error("CheckPasswordHash should return false for wrong password")
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	bytes1, err := GenerateRandomBytes(16)
	if err != nil {
		t.Fatalf("GenerateRandomBytes failed: %v", err)
	}

	if len(bytes1) != 16 {
		t.Errorf("expected 16 bytes, got %d", len(bytes1))
	}

	bytes2, err := GenerateRandomBytes(16)
	if err != nil {
		t.Fatalf("GenerateRandomBytes failed: %v", err)
	}

	// Two random byte sequences should be different
	if string(bytes1) == string(bytes2) {
		t.Error("two random byte sequences should be different")
	}
}

func TestGenerateID(t *testing.T) {
	id1, err := GenerateID()
	if err != nil {
		t.Fatalf("GenerateID failed: %v", err)
	}

	if id1 == "" {
		t.Error("generated ID should not be empty")
	}

	id2, err := GenerateID()
	if err != nil {
		t.Fatalf("GenerateID failed: %v", err)
	}

	if id1 == id2 {
		t.Error("two generated IDs should be different")
	}
}
