package middlewares

import (
	"backend/models"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLanguagesMiddleware(t *testing.T) {
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Accept-Language", "en-US")
	rr := httptest.NewRecorder()

	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		msg, _ := r.Context().Value(models.Lang).(models.LangMsg)
		assert.Equal(t, "not found", msg.Errors.NotFound)
		w.WriteHeader(http.StatusOK)
	})
	
	middleware := Languages(mockHandler)
	middleware.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}
