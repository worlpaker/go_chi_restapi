package handlers

import (
	"backend/models"
	Log "backend/internal/log"
	"encoding/json"
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
		err = ErrEmptyRequestBody
		return
	}
	j := json.NewDecoder(r.Body)
	j.DisallowUnknownFields()
	if err = j.Decode(&data); Log.Err(err) {
		return
	}
	return
}

// Render helper function to handle success response.
func Render(w http.ResponseWriter, code int, v any) error {
	w.WriteHeader(code)

	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, err.Error(), 500)
		return err
	}

	return nil
}

// ErrResponse helper function to handle error request
func ErrResponse(w http.ResponseWriter, code int) error {
	w.WriteHeader(code)
	// print status for the tests
	msg := render{
		"status": code,
		"error":  http.StatusText(code),
	}

	if err := json.NewEncoder(w).Encode(msg); err != nil {
		http.Error(w, err.Error(), 500)
		return err
	}

	return nil
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
