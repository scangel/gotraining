package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/scangel/gotraining/01/internal/crypto"
)

const (
	dataDir   = "data"
	usersFile = "users.enc"
)

type User struct {
	ID            string   `json:"id"`
	Username      string   `json:"username"`
	Email         string   `json:"email"`
	PasswordHash  string   `json:"password_hash"`
	Roles         []string `json:"roles"`
	EmailVerified bool     `json:"email_verified"`
}

type UserStore struct {
	mu            sync.RWMutex
	users         map[string]*User
	filePath      string
	encryptionKey string
}

func NewUserStore(encryptionKey string, dataDirOverride string) (*UserStore, error) {
	dir := dataDir
	if dataDirOverride != "" {
		dir = dataDirOverride
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	filePath := filepath.Join(dir, usersFile)

	store := &UserStore{
		users:         make(map[string]*User),
		filePath:      filePath,
		encryptionKey: encryptionKey,
	}

	if err := store.load(); err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		if err := store.save(); err != nil {
			return nil, err
		}
	}

	return store, nil
}

func (s *UserStore) load() error {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}

	if len(data) == 0 {
		return nil
	}

	decrypted, err := crypto.DecryptData(string(data), s.encryptionKey)
	if err != nil {
		return err
	}

	return json.Unmarshal(decrypted, &s.users)
}

func (s *UserStore) save() error {
	data, err := json.Marshal(s.users)
	if err != nil {
		return err
	}

	encrypted, err := crypto.EncryptData(data, s.encryptionKey)
	if err != nil {
		return err
	}

	return os.WriteFile(s.filePath, []byte(encrypted), 0600)
}

func (s *UserStore) CreateUser(username, email, password string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, u := range s.users {
		if u.Username == username {
			return nil, errors.New("username already exists")
		}
		if u.Email == email {
			return nil, errors.New("email already exists")
		}
	}

	hashedPassword, err := crypto.HashPassword(password)
	if err != nil {
		return nil, err
	}

	id, err := crypto.GenerateID()
	if err != nil {
		return nil, err
	}

	user := &User{
		ID:            id,
		Username:      username,
		Email:         email,
		PasswordHash:  hashedPassword,
		Roles:         []string{"user"},
		EmailVerified: false,
	}

	s.users[user.ID] = user

	if err := s.save(); err != nil {
		return nil, err
	}

	return user, nil
}

func (s *UserStore) GetUserByUsername(username string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, user := range s.users {
		if user.Username == username {
			return user, nil
		}
	}

	return nil, errors.New("user not found")
}

func (s *UserStore) GetUserByID(id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[id]
	if !exists {
		return nil, errors.New("user not found")
	}

	return user, nil
}

func (s *UserStore) ValidatePassword(username, password string) (*User, error) {
	user, err := s.GetUserByUsername(username)
	if err != nil {
		return nil, err
	}

	if !crypto.CheckPasswordHash(password, user.PasswordHash) {
		return nil, errors.New("invalid password")
	}

	return user, nil
}
