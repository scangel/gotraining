package main

import (
	"crypto/sha512"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	issuer        = "http://localhost:8080"
	tokenDuration = 1 * time.Hour
)

type TokenClaims struct {
	Sub           string   `json:"sub"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Roles         []string `json:"roles"`
	jwt.RegisteredClaims
}

type AuthService struct {
	userStore *UserStore
	jwtSecret string
}

func NewAuthService(userStore *UserStore, jwtSecret string) *AuthService {
	return &AuthService{
		userStore: userStore,
		jwtSecret: jwtSecret,
	}
}

func (a *AuthService) generateJWTSecret() []byte {
	hash := sha512.Sum512([]byte(a.jwtSecret))
	return hash[:32]
}

func (a *AuthService) GenerateIDToken(user *User) (string, error) {
	now := time.Now()
	claims := &TokenClaims{
		Sub:           user.ID,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Roles:         user.Roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   user.ID,
			Audience:  jwt.ClaimStrings{issuer},
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenDuration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString(a.generateJWTSecret())
}

func (a *AuthService) GenerateAccessToken(user *User) (string, error) {
	now := time.Now()
	claims := &TokenClaims{
		Sub:   user.ID,
		Roles: user.Roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   user.ID,
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenDuration)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString(a.generateJWTSecret())
}

func (a *AuthService) ValidateToken(tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return a.generateJWTSecret(), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

func (a *AuthService) Authenticate(username, password string) (*User, error) {
	return a.userStore.ValidatePassword(username, password)
}
