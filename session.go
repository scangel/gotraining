package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	sessionPrefix = "session:"
	defaultTTL    = 24 * time.Hour
)

type SessionStore struct {
	client *redis.Client
	ctx    context.Context
}

func NewSessionStore(config *Config) (*SessionStore, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", config.Redis.Host, config.Redis.Port),
		Password: config.Redis.Password,
		DB:       config.Redis.DB,
	})

	ctx := context.Background()

	// Test connection
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &SessionStore{
		client: client,
		ctx:    ctx,
	}, nil
}

// CreateSession creates a new session for the given user ID and returns the session ID
func (s *SessionStore) CreateSession(userID string, ttl time.Duration) (string, error) {
	if ttl == 0 {
		ttl = defaultTTL
	}

	sessionID, err := generateSessionID()
	if err != nil {
		return "", fmt.Errorf("failed to generate session ID: %w", err)
	}

	key := sessionPrefix + sessionID
	err = s.client.Set(s.ctx, key, userID, ttl).Err()
	if err != nil {
		return "", fmt.Errorf("failed to store session: %w", err)
	}

	return sessionID, nil
}

// GetSession retrieves the user ID associated with the given session ID
func (s *SessionStore) GetSession(sessionID string) (string, error) {
	key := sessionPrefix + sessionID
	userID, err := s.client.Get(s.ctx, key).Result()
	if err == redis.Nil {
		return "", fmt.Errorf("session not found")
	}
	if err != nil {
		return "", fmt.Errorf("failed to get session: %w", err)
	}

	return userID, nil
}

// DeleteSession removes the session from Redis
func (s *SessionStore) DeleteSession(sessionID string) error {
	key := sessionPrefix + sessionID
	err := s.client.Del(s.ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	return nil
}

// RefreshSession extends the TTL of an existing session
func (s *SessionStore) RefreshSession(sessionID string, ttl time.Duration) error {
	if ttl == 0 {
		ttl = defaultTTL
	}

	key := sessionPrefix + sessionID
	err := s.client.Expire(s.ctx, key, ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to refresh session: %w", err)
	}

	return nil
}

// Close closes the Redis connection
func (s *SessionStore) Close() error {
	return s.client.Close()
}

// GetClient returns the Redis client for use by other components
func (s *SessionStore) GetClient() *redis.Client {
	return s.client
}

// generateSessionID generates a cryptographically secure random session ID
func generateSessionID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
