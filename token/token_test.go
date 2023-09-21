package token

import (
	"backend/config"
	Log "backend/internal/log"
	"backend/models"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
)

func fakeGenerateJWT(
	user *models.User, signingkey []byte,
	method *jwt.SigningMethodHMAC, exp int64) (string, error) {
	t := jwt.New(method)
	log.SetOutput(io.Discard)
	claims := t.Claims.(jwt.MapClaims)
	claims["Email"] = user.Email
	claims["FullName"] = user.FullName
	claims["NickName"] = user.NickName
	claims["exp"] = exp
	token, err := t.SignedString(signingkey)
	if Log.Err(err) {
		return "", err
	}
	return token, nil
}

func TestGenerateJWT(t *testing.T) {
	log.SetOutput(io.Discard)
	tests := []struct {
		data     *models.User
		expected error
	}{
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				NickName: gofakeit.Username(),
			},
			expected: nil,
		},
	}
	for i, k := range tests {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			_, err := GenerateJWT(k.data)
			assert.Equal(t, k.expected, err)
		})
	}
}

func TestReadJWT(t *testing.T) {
	log.SetOutput(io.Discard)
	tests := []struct {
		data       *models.User
		signingkey []byte
		method     *jwt.SigningMethodHMAC
		time       int64
		expected   error
	}{
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				NickName: gofakeit.Username(),
			},
			signingkey: []byte(config.TokenSecret),
			method:     jwt.SigningMethodHS256,
			time:       time.Now().Add(24 * time.Hour).Unix(),
			expected:   nil,
		},
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				NickName: gofakeit.Username(),
			},
			signingkey: []byte(config.TokenSecret),
			method:     jwt.SigningMethodHS256,
			time:       time.Now().Add(-24 * time.Hour).Unix(),
			expected:   errors.New("token is not verified"),
		},
	}
	for i, k := range tests {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			token, _ := fakeGenerateJWT(k.data, k.signingkey, k.method, k.time)
			req, _ := http.NewRequest(http.MethodGet, "/", nil)
			cookie := &http.Cookie{
				Name:     "Token",
				Value:    token,
				HttpOnly: false,
				MaxAge:   int(time.Hour * 24 * 3),
				Path:     "/",
			}
			req.AddCookie(cookie)
			_, err := ReadJWT(req)
			assert.Equal(t, k.expected, err)
		})
	}
}

func TestTokenValid(t *testing.T) {
	log.SetOutput(io.Discard)
	tests := []struct {
		data       *models.User
		signingkey []byte
		method     *jwt.SigningMethodHMAC
		time       int64
		expected   error
	}{
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				NickName: gofakeit.Username(),
			},
			signingkey: []byte(config.TokenSecret),
			method:     jwt.SigningMethodHS256,
			time:       time.Now().Add(24 * time.Hour).Unix(),
			expected:   nil,
		},
	}
	for i, k := range tests {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			token, _ := fakeGenerateJWT(k.data, k.signingkey, k.method, k.time)
			_, err := TokenValid(token)
			assert.Equal(t, k.expected, err)
		})
	}
}

func TestVerifyToken(t *testing.T) {
	log.SetOutput(io.Discard)
	tests := []struct {
		data       *models.User
		signingkey []byte
		method     *jwt.SigningMethodHMAC
		expected   error
		time       int64
	}{
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				NickName: gofakeit.Username(),
			},
			signingkey: []byte(config.TokenSecret),
			method:     jwt.SigningMethodHS256,
			time:       time.Now().Add(24 * time.Hour).Unix(),
			expected:   nil,
		},
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				NickName: gofakeit.Username(),
			},
			signingkey: []byte("test fails key"),
			method:     jwt.SigningMethodHS256,
			time:       time.Now().Add(24 * time.Hour).Unix(),
			expected:   errors.New("token is not verified"),
		},
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				NickName: gofakeit.Username(),
			},
			signingkey: []byte(config.TokenSecret),
			method:     (*jwt.SigningMethodHMAC)(jwt.SigningMethodRS384),
			time:       time.Now().Add(24 * time.Hour).Unix(),
			expected:   errors.New("token is not verified"),
		},
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				NickName: gofakeit.Username(),
			},
			signingkey: []byte(config.TokenSecret),
			method:     jwt.SigningMethodHS256,
			time:       time.Now().Add(-24 * time.Hour).Unix(),
			expected:   errors.New("token is not verified"),
		},
	}
	for i, k := range tests {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			token, _ := fakeGenerateJWT(k.data, k.signingkey, k.method, k.time)
			_, err := VerifyToken(token)
			assert.Equal(t, k.expected, err)
		})
	}
}
