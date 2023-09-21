package middlewares

import (
	"backend/internal/langmsg"
	Log "backend/internal/log"
	"backend/models"
	"context"

	"net/http"
)

// Languages is a middleware that extracts the language from the "Accept-Language" header
// and adds it to the request context for further processing.
func Languages(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lang_code := r.Header.Get("Accept-Language")
		language, err := langmsg.GetLang(lang_code)
		if Log.Err(err) {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), models.Lang, *language)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
