package middlewares

import (
	"backend/models"
	"backend/pkg/token"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUsersOnlyMiddleware(t *testing.T) {
	token, _ := token.GenerateJWT(&models.User{})
	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "Token", Value: token})

	resp := httptest.NewRecorder()

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	UsersOnly(dummyHandler).ServeHTTP(resp, req)

	assert.Equal(t, http.StatusOK, resp.Code)

}
