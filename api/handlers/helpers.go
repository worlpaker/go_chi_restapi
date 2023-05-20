package handlers

import (
	"backend/models"
	Log "backend/pkg/helpers/log"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type render map[string]interface{}

type GenM interface {
	*models.User | *models.ProfileBio
}

// ReadJSON reads json body by requested model type
func ReadJSON[T GenM](r *http.Request) (data T, err error) {
	if r.Body == nil {
		err = errors.New("empty request body")
		return
	}
	j := json.NewDecoder(r.Body)
	j.DisallowUnknownFields()
	if err = j.Decode(&data); Log.Err(err) {
		return
	}
	return
}

// IsNull checks whether any of the given parameters is an empty string
func IsNull(m ...string) (ok bool) {
	for i := range m {
		if m[i] == "" {
			Log.Err(fmt.Errorf("required parts cannot be empty"))
			ok = true
			return
		}
	}
	return
}

// Render helper function to handle success response
func Render(w http.ResponseWriter, HTTPStatusCode int, v any) error {
	w.WriteHeader(HTTPStatusCode)
	return json.NewEncoder(w).Encode(v)
}

// ErrResponse helper function to handle error request
func ErrResponse(w http.ResponseWriter, HTTPStatusCode int) error {
	w.WriteHeader(HTTPStatusCode)
	msg := render{
		"status": HTTPStatusCode,
		"error":  http.StatusText(HTTPStatusCode),
	}
	return json.NewEncoder(w).Encode(msg)
}

// SetTokenCookie sets a cookie named "Token" in the provided token value.
// If active is true, it creates a cookie.
// If active is false, it deletes a cookie.
func SetTokenCookie(w http.ResponseWriter, token string, active bool) {
	var cookie *http.Cookie
	if active {
		cookie = &http.Cookie{
			Name:     "Token",
			Value:    token,
			HttpOnly: false,
			MaxAge:   int(time.Hour * 24),
			Path:     "/",
		}
	} else {
		cookie = &http.Cookie{
			Name:     "Token",
			Value:    "",
			HttpOnly: false,
			Path:     "/",
			MaxAge:   0,
			Expires:  time.Unix(0, 0),
		}
	}
	if v := cookie.String(); v != "" {
		w.Header().Add("Set-Cookie", v)
	}
}
