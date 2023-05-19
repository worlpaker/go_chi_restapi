package routers

import (
	"backend/models"
	Log "backend/pkg/helpers/log"
	"backend/pkg/msglang"
	"backend/pkg/token"
	"context"

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

// MiddlewareLang is a middleware that extracts the language from the "Accept-Language" header
// and adds it to the request context for further processing.
func MiddlewareLang(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lang_code := r.Header.Get("Accept-Language")
		language, err := msglang.GetLang(lang_code)
		if Log.Err(err) {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), models.Lang, *language)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
