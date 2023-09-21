package middlewares

import (
	Log "backend/pkg/helpers/log"
	"backend/pkg/token"

	"net/http"
)

// UsersOnly middleware restricts access
func UsersOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t, err := r.Cookie("Token")
		if Log.Err(err) {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		if _, err := token.TokenValid(t.Value); Log.Err(err) {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
