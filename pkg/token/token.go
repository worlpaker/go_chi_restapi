package token

import (
	"backend/config"
	"backend/models"
	Log "backend/pkg/helpers/log"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
)

// GenerateJWT to authorize user on http cookies
func GenerateJWT(user *models.User) (string, error) {
	claims := jwt.MapClaims{
		"Email":    user.Email,
		"FullName": user.FullName,
		"NickName": user.NickName,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := t.SignedString([]byte(config.TokenSecret))
	if Log.Err(err) {
		return "", err
	}
	return token, nil
}

// ReadJWT reads jwt token, checks token and converts to *User
func ReadJWT(r *http.Request) (*models.User, error) {
	t, _ := r.Cookie("Token")
	token, err := TokenValid(t.Value)
	if Log.Err(err) {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		Log.Err(fmt.Errorf("error reading token"))
		return nil, fmt.Errorf("error reading token")
	}
	data := JWTtoData(claims)
	return data, nil
}

// JWTtoData reads jwt claim fields
func JWTtoData(claims jwt.MapClaims) *models.User {
	email, _ := claims["Email"].(string)
	nickname, _ := claims["NickName"].(string)
	fullname, _ := claims["FullName"].(string)
	data := &models.User{
		Email:    email,
		NickName: nickname,
		FullName: fullname,
	}
	return data
}

// TokenValid checks validation
func TokenValid(t string) (*jwt.Token, error) {
	token, err := VerifyToken(t)
	if Log.Err(err) {
		return nil, err
	}
	if _, ok := token.Claims.(*jwt.StandardClaims); !ok && !token.Valid {
		Log.Err(fmt.Errorf("token is invalid"))
		return nil, fmt.Errorf("token is invalid")
	}
	return token, nil
}

// VerifyToken verifies token method
func VerifyToken(t string) (*jwt.Token, error) {
	token, err := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			Log.Err(fmt.Errorf("unexpected signing method: %v", token.Header["alg"]))
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(config.TokenSecret), nil
	})
	if Log.Err(err) {
		return nil, errors.New("token is not verified")
	}
	return token, nil
}
