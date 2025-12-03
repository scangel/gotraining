package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	csrfTokenLength = 32
	csrfCookieName  = "csrf_token"
	csrfHeaderName  = "X-CSRF-Token"
	csrfFormField   = "csrf_token"
	csrfTokenTTL    = 24 * time.Hour
)

// RateLimiter provides rate limiting using Redis
type RateLimiter struct {
	client         *redis.Client
	ctx            context.Context
	requestsPerMin int
	enabled        bool
}

// LoginAttemptTracker tracks failed login attempts for brute force protection
type LoginAttemptTracker struct {
	client      *redis.Client
	ctx         context.Context
	maxAttempts int
	lockoutTime time.Duration
	enabled     bool
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(client *redis.Client, requestsPerMin int) *RateLimiter {
	enabled := client != nil
	if !enabled {
		log.Println("Warning: Rate limiter disabled (no Redis connection)")
	}
	return &RateLimiter{
		client:         client,
		ctx:            context.Background(),
		requestsPerMin: requestsPerMin,
		enabled:        enabled,
	}
}

// NewLoginAttemptTracker creates a new login attempt tracker
func NewLoginAttemptTracker(client *redis.Client, maxAttempts int, lockoutTime time.Duration) *LoginAttemptTracker {
	enabled := client != nil
	if !enabled {
		log.Println("Warning: Login attempt tracker disabled (no Redis connection)")
	}
	return &LoginAttemptTracker{
		client:      client,
		ctx:         context.Background(),
		maxAttempts: maxAttempts,
		lockoutTime: lockoutTime,
		enabled:     enabled,
	}
}

// Allow checks if the request should be allowed based on rate limiting
func (rl *RateLimiter) Allow(ip string) (bool, error) {
	if !rl.enabled {
		return true, nil
	}

	key := fmt.Sprintf("rate_limit:%s", ip)

	// Increment counter
	count, err := rl.client.Incr(rl.ctx, key).Result()
	if err != nil {
		log.Printf("Rate limit check failed: %v", err)
		return true, nil // Allow on error to prevent blocking legitimate users
	}

	// Set expiry on first request
	if count == 1 {
		rl.client.Expire(rl.ctx, key, time.Minute)
	}

	return count <= int64(rl.requestsPerMin), nil
}

// GetRemainingRequests returns the number of remaining requests
func (rl *RateLimiter) GetRemainingRequests(ip string) int {
	if !rl.enabled {
		return rl.requestsPerMin
	}

	key := fmt.Sprintf("rate_limit:%s", ip)
	count, err := rl.client.Get(rl.ctx, key).Int()
	if err != nil {
		return rl.requestsPerMin
	}

	remaining := rl.requestsPerMin - count
	if remaining < 0 {
		return 0
	}
	return remaining
}

// RecordFailedAttempt records a failed login attempt
func (t *LoginAttemptTracker) RecordFailedAttempt(username string) error {
	if !t.enabled {
		return nil
	}

	key := fmt.Sprintf("login_attempts:%s", username)

	// Increment counter
	count, err := t.client.Incr(t.ctx, key).Result()
	if err != nil {
		return err
	}

	// Set/refresh expiry
	if count == 1 {
		t.client.Expire(t.ctx, key, t.lockoutTime)
	}

	return nil
}

// IsBlocked checks if the user is blocked due to too many failed attempts
func (t *LoginAttemptTracker) IsBlocked(username string) (bool, int, error) {
	if !t.enabled {
		return false, 0, nil
	}

	key := fmt.Sprintf("login_attempts:%s", username)

	attempts, err := t.client.Get(t.ctx, key).Int()
	if err == redis.Nil {
		return false, t.maxAttempts, nil
	}
	if err != nil {
		return false, t.maxAttempts, err
	}

	remaining := t.maxAttempts - attempts
	if remaining < 0 {
		remaining = 0
	}

	return attempts >= t.maxAttempts, remaining, nil
}

// ResetAttempts clears the failed attempts for a user (called on successful login)
func (t *LoginAttemptTracker) ResetAttempts(username string) error {
	if !t.enabled {
		return nil
	}

	key := fmt.Sprintf("login_attempts:%s", username)
	return t.client.Del(t.ctx, key).Err()
}

// GetLockoutTimeRemaining returns the remaining lockout time in seconds
func (t *LoginAttemptTracker) GetLockoutTimeRemaining(username string) int {
	if !t.enabled {
		return 0
	}

	key := fmt.Sprintf("login_attempts:%s", username)
	ttl, err := t.client.TTL(t.ctx, key).Result()
	if err != nil {
		return 0
	}
	return int(ttl.Seconds())
}

// In-memory rate limiter for when Redis is not available
type InMemoryRateLimiter struct {
	requests map[string][]time.Time
	mu       sync.RWMutex
	limit    int
	window   time.Duration
}

func NewInMemoryRateLimiter(limit int, window time.Duration) *InMemoryRateLimiter {
	limiter := &InMemoryRateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
	// Start cleanup goroutine
	go limiter.cleanup()
	return limiter
}

func (rl *InMemoryRateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-rl.window)

	// Filter out old requests
	var validRequests []time.Time
	for _, t := range rl.requests[ip] {
		if t.After(windowStart) {
			validRequests = append(validRequests, t)
		}
	}

	if len(validRequests) >= rl.limit {
		rl.requests[ip] = validRequests
		return false
	}

	rl.requests[ip] = append(validRequests, now)
	return true
}

func (rl *InMemoryRateLimiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		windowStart := now.Add(-rl.window)

		for ip, times := range rl.requests {
			var validRequests []time.Time
			for _, t := range times {
				if t.After(windowStart) {
					validRequests = append(validRequests, t)
				}
			}
			if len(validRequests) == 0 {
				delete(rl.requests, ip)
			} else {
				rl.requests[ip] = validRequests
			}
		}
		rl.mu.Unlock()
	}
}

// rateLimitMiddleware applies rate limiting to requests
func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract IP address
		ip := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			ip = strings.Split(forwarded, ",")[0]
		}
		ip = strings.Split(ip, ":")[0]

		allowed, _ := s.rateLimiter.Allow(ip)
		if !allowed {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "Too many requests. Please try again later.", http.StatusTooManyRequests)
			return
		}

		// Add rate limit headers
		remaining := s.rateLimiter.GetRemainingRequests(ip)
		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", s.rateLimiter.requestsPerMin))
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))

		next.ServeHTTP(w, r)
	})
}

// generateCSRFToken generates a cryptographically secure random CSRF token
func generateCSRFToken() (string, error) {
	bytes := make([]byte, csrfTokenLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// CSRFTokenStore manages CSRF tokens using Redis
type CSRFTokenStore struct {
	client  *redis.Client
	ctx     context.Context
	enabled bool
}

// NewCSRFTokenStore creates a new CSRF token store
func NewCSRFTokenStore(client *redis.Client) *CSRFTokenStore {
	enabled := client != nil
	if !enabled {
		log.Println("Warning: CSRF token store disabled (no Redis connection)")
	}
	return &CSRFTokenStore{
		client:  client,
		ctx:     context.Background(),
		enabled: enabled,
	}
}

// GenerateAndStore generates a new CSRF token and stores it in Redis
func (c *CSRFTokenStore) GenerateAndStore(sessionID string) (string, error) {
	token, err := generateCSRFToken()
	if err != nil {
		return "", err
	}

	if c.enabled {
		key := fmt.Sprintf("csrf:%s", sessionID)
		if err := c.client.Set(c.ctx, key, token, csrfTokenTTL).Err(); err != nil {
			return "", err
		}
	}

	return token, nil
}

// Validate checks if the provided token matches the stored token
func (c *CSRFTokenStore) Validate(sessionID, token string) bool {
	if !c.enabled {
		// If Redis is not available, fall back to cookie comparison
		return true
	}

	key := fmt.Sprintf("csrf:%s", sessionID)
	storedToken, err := c.client.Get(c.ctx, key).Result()
	if err != nil {
		return false
	}

	return storedToken == token
}

// csrfMiddleware provides CSRF protection for state-changing requests
func (s *Server) csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip CSRF check for safe methods
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			// For GET requests, ensure CSRF token exists in cookie
			_, err := r.Cookie(csrfCookieName)
			if err == http.ErrNoCookie {
				// Generate new CSRF token
				token, err := generateCSRFToken()
				if err != nil {
					log.Printf("Failed to generate CSRF token: %v", err)
					next.ServeHTTP(w, r)
					return
				}

				http.SetCookie(w, &http.Cookie{
					Name:     csrfCookieName,
					Value:    token,
					Path:     "/",
					MaxAge:   86400,
					HttpOnly: false, // JavaScript에서 접근 가능해야 함
					Secure:   s.config.TLS.Enabled,
					SameSite: http.SameSiteStrictMode,
				})
			}
			next.ServeHTTP(w, r)
			return
		}

		// For state-changing methods (POST, PUT, DELETE, PATCH), validate CSRF token
		cookieToken, err := r.Cookie(csrfCookieName)
		if err != nil {
			http.Error(w, "CSRF token missing", http.StatusForbidden)
			return
		}

		// Get token from header or form
		requestToken := r.Header.Get(csrfHeaderName)
		if requestToken == "" {
			requestToken = r.FormValue(csrfFormField)
		}

		if requestToken == "" {
			http.Error(w, "CSRF token not provided", http.StatusForbidden)
			return
		}

		// Compare tokens (Double Submit Cookie pattern)
		if cookieToken.Value != requestToken {
			http.Error(w, "CSRF token invalid", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
