package handlers

import (
	"backend/models"
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestReadJSON(t *testing.T) {
	log.SetOutput(io.Discard)
	data := &models.ProfileBio{
		NickName: "Test1",
		Info:     "Test2",
	}
	payload, err := json.Marshal(data)
	assert.Nil(t, err)
	req := httptest.NewRequest(http.MethodPost, "/readjson", bytes.NewBuffer(payload))
	req.Header.Set("Content-Type", "application/json")
	json_data, err := ReadJSON[*models.ProfileBio](req)
	assert.Nil(t, err)
	assert.Equal(t, "Test1", json_data.NickName)
	assert.Equal(t, "Test2", json_data.Info)
}

func TestRender(t *testing.T) {
	log.SetOutput(io.Discard)
	_ = httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	msg := map[string]interface{}{
		"status":  http.StatusOK,
		"message": "succes!",
	}
	Render(w, http.StatusOK, msg)
	res := w.Result()
	defer res.Body.Close()
	actual_body, _ := io.ReadAll(res.Body)
	expected_body, _ := json.Marshal(&msg)
	assert.JSONEq(t, string(expected_body), string(actual_body))
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func TestErrResponse(t *testing.T) {
	log.SetOutput(io.Discard)
	_ = httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	ErrResponse(w, http.StatusBadGateway)
	res := w.Result()
	defer res.Body.Close()
	actual_body, _ := io.ReadAll(res.Body)
	msg := map[string]interface{}{
		"status": http.StatusBadGateway,
		"error":  http.StatusText(http.StatusBadGateway),
	}
	expected_body, _ := json.Marshal(&msg)
	assert.JSONEq(t, string(expected_body), string(actual_body))
	assert.Equal(t, http.StatusBadGateway, res.StatusCode)
}

func TestIsParamNull(t *testing.T) {
	log.SetOutput(io.Discard)
	testCases := []struct {
		input    []string
		expected bool
	}{
		{[]string{"a", "b", "c"}, false},
		{[]string{"a", "", "c"}, true},
		{[]string{"", "", ""}, true},
		{[]string{""}, true},
		{[]string{}, false},
	}

	for _, k := range testCases {
		actual := IsNull(k.input...)
		assert.Equal(t, k.expected, actual)
	}
}

func TestSetTokenCookie(t *testing.T) {
	log.SetOutput(io.Discard)
	w := httptest.NewRecorder()
	activeToken := "example_token"
	SetTokenCookie(w, activeToken, true)
	cookies := w.Result().Cookies()
	assert.Len(t, cookies, 1)
	cookie := cookies[0]
	assert.Equal(t, "Token", cookie.Name)
	assert.Equal(t, activeToken, cookie.Value)
	assert.Equal(t, "/", cookie.Path)
	assert.False(t, cookie.HttpOnly)
	assert.Greater(t, cookie.MaxAge, 0)
	w = httptest.NewRecorder()
	SetTokenCookie(w, "", false)
	cookies = w.Result().Cookies()
	assert.Len(t, cookies, 1)
	cookie = cookies[0]
	assert.Equal(t, "Token", cookie.Name)
	assert.Empty(t, cookie.Value)
	assert.Equal(t, "/", cookie.Path)
	assert.False(t, cookie.HttpOnly)
	assert.Equal(t, time.Unix(0, 0).UTC(), cookie.Expires.UTC())
	assert.Equal(t, 0, cookie.MaxAge)
}
