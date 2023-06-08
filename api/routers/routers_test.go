package routers

import (
	"backend/api/handlers"
	"backend/config"
	"backend/database"
	"backend/database/pqdb"
	"backend/models"
	"backend/pkg/token"
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/go-chi/chi"
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
)

func ExecuteRequest(req *http.Request, s *chi.Mux) *httptest.ResponseRecorder {
	log.SetOutput(io.Discard)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	return rr
}

func FakeNewServer(t *testing.T) (*Server, sqlmock.Sqlmock) {
	log.SetOutput(io.Discard)
	r := chi.NewRouter()
	d, m := NewMock(t)
	s := &Server{
		Router: r,
		Handlers: &handlers.Server{
			DB: &database.DB{
				Postgres: &pqdb.Server{
					Client: d,
				},
			},
		},
	}
	s.SetupRouters()
	return s, m
}

func NewMock(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	log.SetOutput(io.Discard)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Errorf("error in mock database connection: %s", err)
	}
	return db, mock
}

func ConvertDatatoBuf(t *testing.T, data any) *bytes.Buffer {
	log.SetOutput(io.Discard)
	databuf := new(bytes.Buffer)
	if err := json.NewEncoder(databuf).Encode(data); err != nil {
		t.Errorf("error when convert json to buf %v", err)
	}
	return databuf
}

func FakeGenerateJWT(t *testing.T, user *models.User, signingkey []byte,
	method *jwt.SigningMethodHMAC, exp int64) (string, error) {
	log.SetOutput(io.Discard)
	jwt_token := jwt.New(method)
	claims := jwt_token.Claims.(jwt.MapClaims)
	claims["Email"] = user.Email
	claims["FullName"] = user.FullName
	claims["NickName"] = user.NickName
	claims["exp"] = exp
	token, err := jwt_token.SignedString(signingkey)
	assert.Nil(t, err)
	return token, nil
}

func TestHome(t *testing.T) {
	log.SetOutput(io.Discard)
	s, _ := FakeNewServer(t)
	req, err := http.NewRequest(http.MethodGet, "/", nil)
	assert.Nil(t, err)
	response := ExecuteRequest(req, s.Router)
	assert.Equal(t, http.StatusOK, response.Code)
}

func TestRegister(t *testing.T) {
	log.SetOutput(io.Discard)
	s, mock := FakeNewServer(t)
	test_fullname := "test and test"
	data := []struct {
		data          *models.User
		expected_code int
	}{
		{
			data: &models.User{
				Email:    "test@test.com",
				Password: "test123",
				NickName: "test",
				FullName: &test_fullname,
			},
			expected_code: http.StatusCreated,
		},
		{
			data: &models.User{
				Email:    "test@test.com",
				Password: "test123",
				NickName: "test",
			},
			expected_code: http.StatusCreated,
		},
		{
			data: &models.User{
				Email:    "test1@test.com",
				Password: "test1234568",
				NickName: "test2",
			},
			expected_code: http.StatusCreated,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			mock.ExpectBegin()
			mock.ExpectExec(pqdb.Sql_createuser).
				WillReturnResult(sqlmock.NewResult(1, 1))
			mock.ExpectCommit()
			databuf := ConvertDatatoBuf(t, k.data)
			req, err := http.NewRequest("POST", "/register", databuf)
			assert.Nil(t, err)
			response := ExecuteRequest(req, s.Router)
			assert.Equal(t, k.expected_code, response.Code)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
}

func TestRegisterError(t *testing.T) {
	log.SetOutput(io.Discard)
	s, mock := FakeNewServer(t)
	test_f := "testfull"
	data := []struct {
		data          *models.User
		sql           bool
		expected_code int
	}{
		{
			data: &models.User{
				Email:    "test@test.com",
				Password: "test123",
				NickName: "test",
				FullName: &test_f,
			},
			sql:           true,
			expected_code: http.StatusInternalServerError,
		},
		{
			data: &models.User{
				Password: "test123",
			},
			expected_code: http.StatusBadRequest,
		},
		{
			data: &models.User{
				Email:    "test@test.com",
				Password: "test123",
			},
			expected_code: http.StatusBadRequest,
		},
		{
			data: &models.User{
				Email: "test@test.com",
				Password: `testtesttesttesttest
				testtesttesttesttesttest
				testtesttesttesttesttesttesttesttest`,
				NickName: "test",
			},
			expected_code: http.StatusInternalServerError,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			//test registered email
			if k.sql {
				mock.ExpectBegin()
				mock.ExpectExec(pqdb.Sql_createuser).
					WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectCommit()
				err := s.Handlers.DB.Postgres.SQL_CreateUser(k.data)
				assert.Nil(t, err)
			}
			databuf := ConvertDatatoBuf(t, k.data)
			req, err := http.NewRequest("POST", "/register", databuf)
			assert.Nil(t, err)
			response := ExecuteRequest(req, s.Router)
			assert.Equal(t, k.expected_code, response.Code)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
	badJSON := []struct {
		data          any
		expected_code int
	}{
		{
			data:          "test",
			expected_code: http.StatusBadRequest,
		},
		{
			data: &models.ProfileBio{
				NickName: "test",
			},
			expected_code: http.StatusBadRequest,
		},
	}
	for i, k := range badJSON {
		t.Run(fmt.Sprintln("no: ", len(data)+i+1), func(t *testing.T) {
			databuf := ConvertDatatoBuf(t, k.data)
			req, err := http.NewRequest("POST", "/register", databuf)
			assert.Nil(t, err)
			response := ExecuteRequest(req, s.Router)
			assert.Equal(t, k.expected_code, response.Code)
		})
	}
}

func TestLogin(t *testing.T) {
	log.SetOutput(io.Discard)
	s, mock := FakeNewServer(t)
	data := []struct {
		data          *models.User
		expected_code int
	}{
		{
			data: &models.User{
				Email:    "test@test.com",
				Password: "test123",
			},
			expected_code: http.StatusOK,
		},
		{
			data: &models.User{
				Email:    "test@test.com",
				Password: "test123",
				NickName: "test",
			},
			expected_code: http.StatusOK,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			pwd, _ := pqdb.HashPassword(k.data.Password)
			rows := sqlmock.NewRows([]string{"Email", "Pwd", "NickName", "FullName"}).
				AddRow(k.data.Email, pwd, k.data.NickName, k.data.FullName)
			mock.ExpectBegin()
			mock.ExpectQuery(pqdb.Sql_readuser).
				WithArgs(k.data.Email).
				WillReturnRows(rows)
			mock.ExpectCommit()
			databuf := ConvertDatatoBuf(t, k.data)
			req, _ := http.NewRequest("POST", "/login", databuf)
			response := ExecuteRequest(req, s.Router)
			assert.Equal(t, k.expected_code, response.Code)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
}

func TestLoginError(t *testing.T) {
	log.SetOutput(io.Discard)
	s, mock := FakeNewServer(t)
	data := []struct {
		data          *models.User
		sql           bool
		expected_code int
	}{
		{
			data: &models.User{
				Password: "test123",
				NickName: "test",
			},
			expected_code: http.StatusBadRequest,
		},
		{
			data: &models.User{
				Email:    "test1234@test.com",
				Password: "test",
			},
			sql:           true,
			expected_code: http.StatusInternalServerError,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			//test wrong password
			if k.sql {
				mock.ExpectBegin()
				mock.ExpectExec(pqdb.Sql_createuser).
					WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectCommit()
				err := s.Handlers.DB.Postgres.SQL_CreateUser(k.data)
				assert.Nil(t, err)
				pwd, _ := pqdb.HashPassword(k.data.Password + "fails.")
				rows := sqlmock.NewRows([]string{"Email", "Pwd", "NickName", "FullName"}).
					AddRow(k.data.Email, pwd, k.data.NickName, k.data.FullName)
				mock.ExpectBegin()
				mock.ExpectQuery(pqdb.Sql_readuser).
					WithArgs(k.data.Email).
					WillReturnRows(rows)
				mock.ExpectRollback()
			}
			databuf := ConvertDatatoBuf(t, k.data)
			req, _ := http.NewRequest("POST", "/login", databuf)
			response := ExecuteRequest(req, s.Router)
			assert.Equal(t, k.expected_code, response.Code)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
	badJSON := []struct {
		data          any
		expected_code int
	}{
		{
			data:          "test",
			expected_code: http.StatusBadRequest,
		},
		{
			data: &models.ProfileBio{
				NickName: "test",
			},
			expected_code: http.StatusBadRequest,
		},
	}
	for i, k := range badJSON {
		t.Run(fmt.Sprintln("no: ", len(data)+i+1), func(t *testing.T) {
			databuf := ConvertDatatoBuf(t, k.data)
			req, _ := http.NewRequest("POST", "/login", databuf)
			response := ExecuteRequest(req, s.Router)
			assert.Equal(t, k.expected_code, response.Code)
		})
	}
}

func TestBioPublic(t *testing.T) {
	log.SetOutput(io.Discard)
	s, mock := FakeNewServer(t)
	data := []struct {
		data          *models.ProfileBio
		expected_code int
	}{
		{
			data: &models.ProfileBio{
				NickName: "testnick",
				Info:     "test info",
			},
			expected_code: http.StatusOK,
		},
		{
			data: &models.ProfileBio{
				NickName: "testnick2",
				Info:     "1test info22",
			},
			expected_code: http.StatusOK,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			rows := sqlmock.NewRows([]string{"Info"}).
				AddRow(k.data.Info)
			mock.ExpectBegin()
			mock.ExpectQuery(pqdb.Sql_readbio).
				WithArgs(k.data.NickName).
				WillReturnRows(rows)
			mock.ExpectCommit()
			url := fmt.Sprintf("/info/%s", k.data.NickName)
			req, _ := http.NewRequest("GET", url, nil)
			response := ExecuteRequest(req, s.Router)
			assert.Equal(t, k.expected_code, response.Code)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
}

func TestBioPublicError(t *testing.T) {
	log.SetOutput(io.Discard)
	s, mock := FakeNewServer(t)
	data := []struct {
		data          *models.ProfileBio
		sql           bool
		expected_code int
	}{
		{
			data: &models.ProfileBio{
				NickName: "",
				Info:     "test info",
			},
			expected_code: http.StatusNotFound,
		},
		{
			data: &models.ProfileBio{
				Info: "test info",
			},
			expected_code: http.StatusNotFound,
		},
		{
			data: &models.ProfileBio{
				NickName: "testnick",
				Info:     "test info",
			},
			sql:           true,
			expected_code: http.StatusInternalServerError,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			if k.sql {
				mock.ExpectBegin()
				mock.ExpectQuery(pqdb.Sql_readbio).
					WithArgs(k.data.NickName).
					WillReturnError(sql.ErrConnDone)
				mock.ExpectRollback()
			}
			url := fmt.Sprintf("/info/%s", k.data.NickName)
			req, _ := http.NewRequest("GET", url, nil)
			response := ExecuteRequest(req, s.Router)
			assert.Equal(t, k.expected_code, response.Code)
			assert.Nil(t, mock.ExpectationsWereMet())

		})
	}
}

func TestProfile(t *testing.T) {
	log.SetOutput(io.Discard)
	s, mock := FakeNewServer(t)
	data := []struct {
		data          *models.User
		bio           *models.ProfileBio
		cookie        bool
		expected_code int
	}{
		{
			data: &models.User{
				Email:    "test@test.com",
				Password: "test123",
			},
			bio: &models.ProfileBio{
				NickName: "testnick",
				Info:     "test info",
			},
			cookie:        true,
			expected_code: http.StatusOK,
		},
		{
			data: &models.User{
				Email:    "test@test.com",
				Password: "test123",
				NickName: "testnick",
			},
			bio: &models.ProfileBio{
				NickName: "testnick",
				Info:     "test info",
			},
			cookie:        true,
			expected_code: http.StatusOK,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			rows := sqlmock.NewRows([]string{"Info"}).
				AddRow(k.bio.Info)
			mock.ExpectBegin()
			mock.ExpectQuery(pqdb.Sql_readbio).
				WithArgs(k.data.NickName).
				WillReturnRows(rows)
			mock.ExpectCommit()
			req, _ := http.NewRequest("GET", "/profile", nil)
			if k.cookie {
				token, err := token.GenerateJWT(k.data)
				assert.Nil(t, err)
				cookie := &http.Cookie{
					Name:     "Token",
					Value:    token,
					HttpOnly: false,
					MaxAge:   int(time.Hour * 24 * 3),
					Path:     "/",
				}
				req.AddCookie(cookie)
			}
			response := ExecuteRequest(req, s.Router)
			assert.Equal(t, k.expected_code, response.Code)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
}

func TestProfileError(t *testing.T) {
	log.SetOutput(io.Discard)
	s, mock := FakeNewServer(t)
	data := []struct {
		data          *models.User
		bio           *models.ProfileBio
		sql           bool
		cookie        bool
		expected_code int
	}{
		{
			data: &models.User{
				Email:    "test@test.com",
				Password: "test123",
				NickName: "testnick",
			},
			bio: &models.ProfileBio{
				NickName: "testnick",
				Info:     "test info",
			},
			expected_code: http.StatusUnauthorized,
		},
		{
			data: &models.User{
				Email:    "test@test.com",
				Password: "test123",
				NickName: "testnick",
			},
			bio: &models.ProfileBio{
				NickName: "testnick",
				Info:     "test info",
			},
			sql:           true,
			cookie:        true,
			expected_code: http.StatusInternalServerError,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/profile", nil)
			if k.cookie && k.sql {
				mock.ExpectBegin()
				mock.ExpectQuery(pqdb.Sql_readbio).
					WithArgs(k.data.NickName).
					WillReturnError(sql.ErrConnDone)
				mock.ExpectRollback()
				token, err := token.GenerateJWT(k.data)
				assert.Nil(t, err)
				cookie := &http.Cookie{
					Name:     "Token",
					Value:    token,
					HttpOnly: false,
					MaxAge:   int(time.Hour * 24 * 3),
					Path:     "/",
				}
				req.AddCookie(cookie)
			}
			response := ExecuteRequest(req, s.Router)
			assert.Equal(t, k.expected_code, response.Code)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
	Unauthorized := []struct {
		data       *models.User
		signingkey []byte
		method     *jwt.SigningMethodHMAC
		time       int64
		expected   int
	}{
		{
			data: &models.User{
				Email:    "test@test.com",
				NickName: "testnick",
			},
			signingkey: []byte("testfailtoken"),
			method:     jwt.SigningMethodHS256,
			time:       time.Now().Add(24 * time.Hour).Unix(),
			expected:   http.StatusUnauthorized,
		},
		{
			data: &models.User{
				Email:    "test@test.com",
				NickName: "testnick",
			},
			signingkey: []byte(config.TokenSecret),
			method:     jwt.SigningMethodHS256,
			time:       time.Now().Add(-24 * time.Hour).Unix(),
			expected:   http.StatusUnauthorized,
		},
	}
	for i, k := range Unauthorized {
		t.Run(fmt.Sprintln("no: ", len(data)+i+1), func(t *testing.T) {
			token, _ := FakeGenerateJWT(t, k.data, k.signingkey, k.method, k.time)
			req, _ := http.NewRequest("GET", "/profile", nil)
			cookie := &http.Cookie{
				Name:     "Token",
				Value:    token,
				HttpOnly: false,
				MaxAge:   int(time.Hour * 24 * 3),
				Path:     "/",
			}
			req.AddCookie(cookie)
			response := ExecuteRequest(req, s.Router)
			assert.Equal(t, k.expected, response.Code)
		})
	}
}

func TestAddBio(t *testing.T) {
	log.SetOutput(io.Discard)
	s, mock := FakeNewServer(t)
	data := []struct {
		data          *models.User
		bio           *models.ProfileBio
		cookie        bool
		expected_code int
	}{
		{
			data: &models.User{
				Email:    "test@test.com",
				Password: "test123",
			},
			bio: &models.ProfileBio{
				NickName: "testnick",
				Info:     "test info",
			},
			cookie:        true,
			expected_code: http.StatusCreated,
		},
		{
			data: &models.User{
				Email:    "test@test.com",
				Password: "test123",
				NickName: "testnick",
			},
			bio: &models.ProfileBio{
				NickName: "testnick",
				Info:     "test info",
			},
			cookie:        true,
			expected_code: http.StatusCreated,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			mock.ExpectBegin()
			mock.ExpectExec(pqdb.Sql_addbio).
				WillReturnResult(sqlmock.NewResult(1, 1))
			mock.ExpectCommit()
			databuf := ConvertDatatoBuf(t, k.bio)
			req, _ := http.NewRequest("POST", "/profile/info", databuf)
			if k.cookie {
				token, err := token.GenerateJWT(k.data)
				assert.Nil(t, err)
				cookie := &http.Cookie{
					Name:     "Token",
					Value:    token,
					HttpOnly: false,
					MaxAge:   int(time.Hour * 24 * 3),
					Path:     "/",
				}
				req.AddCookie(cookie)
			}
			response := ExecuteRequest(req, s.Router)
			assert.Equal(t, k.expected_code, response.Code)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
}

func TestAddBioError(t *testing.T) {
	log.SetOutput(io.Discard)
	s, mock := FakeNewServer(t)
	data := []struct {
		data          *models.User
		bio           *models.ProfileBio
		sql           bool
		cookie        bool
		expected_code int
	}{
		{
			data: &models.User{
				Email:    "test@test.com",
				Password: "test123",
				NickName: "testnick",
			},
			bio: &models.ProfileBio{
				NickName: "testnick",
				Info:     "test info",
			},
			expected_code: http.StatusUnauthorized,
		},
		{
			data: &models.User{
				Email:    "test2@test.com",
				Password: "test1234",
				NickName: "testnick2",
			},
			bio: &models.ProfileBio{
				NickName: "testnick2",
				Info:     "test info",
			},
			expected_code: http.StatusUnauthorized,
		},
		{
			data: &models.User{
				Email:    "test2@test.com",
				Password: "test1234",
				NickName: "testnick2",
			},
			bio: &models.ProfileBio{
				NickName: "testnick2",
				Info:     "test info",
			},
			sql:           true,
			cookie:        true,
			expected_code: http.StatusInternalServerError,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			databuf := ConvertDatatoBuf(t, k.bio)
			req, _ := http.NewRequest("POST", "/profile/info", databuf)
			if k.cookie && k.sql {
				mock.ExpectBegin()
				mock.ExpectExec(pqdb.Sql_addbio).
					WillReturnError(sql.ErrConnDone)
				mock.ExpectRollback()
				token, err := token.GenerateJWT(k.data)
				assert.Nil(t, err)
				cookie := &http.Cookie{
					Name:     "Token",
					Value:    token,
					HttpOnly: false,
					MaxAge:   int(time.Hour * 24 * 3),
					Path:     "/",
				}
				req.AddCookie(cookie)
			}
			response := ExecuteRequest(req, s.Router)
			assert.Equal(t, k.expected_code, response.Code)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
	badJSON := []struct {
		data          *models.User
		expected_code int
	}{
		{
			data: &models.User{
				NickName: "test",
			},
			expected_code: http.StatusBadRequest,
		},
	}
	for i, k := range badJSON {
		t.Run(fmt.Sprintln("no: ", len(data)+i+1), func(t *testing.T) {
			token, err := token.GenerateJWT(k.data)
			assert.Nil(t, err)
			cookie := &http.Cookie{
				Name:     "Token",
				Value:    token,
				HttpOnly: false,
				MaxAge:   int(time.Hour * 24 * 3),
				Path:     "/",
			}
			databuf := ConvertDatatoBuf(t, k.data)
			req, _ := http.NewRequest("POST", "/profile/info", databuf)
			req.AddCookie(cookie)
			response := ExecuteRequest(req, s.Router)
			assert.Equal(t, k.expected_code, response.Code)
		})
	}
}

func TestEditBio(t *testing.T) {
	log.SetOutput(io.Discard)
	s, mock := FakeNewServer(t)
	data := []struct {
		data          *models.User
		bio           *models.ProfileBio
		cookie        bool
		expected_code int
	}{
		{
			data: &models.User{
				Email:    "test@test.com",
				Password: "test123",
			},
			bio: &models.ProfileBio{
				NickName: "testnick",
				Info:     "test info",
			},
			cookie:        true,
			expected_code: http.StatusOK,
		},
		{
			data: &models.User{
				Email:    "test@test.com",
				Password: "test123",
				NickName: "testnick",
			},
			bio: &models.ProfileBio{
				NickName: "testnick",
				Info:     "test info",
			},
			cookie:        true,
			expected_code: http.StatusOK,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			mock.ExpectBegin()
			mock.ExpectExec(pqdb.Sql_editbio).
				WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectCommit()
			databuf := ConvertDatatoBuf(t, k.bio)
			req, _ := http.NewRequest("PUT", "/profile/info", databuf)
			if k.cookie {
				token, err := token.GenerateJWT(k.data)
				assert.Nil(t, err)
				cookie := &http.Cookie{
					Name:     "Token",
					Value:    token,
					HttpOnly: false,
					MaxAge:   int(time.Hour * 24 * 3),
					Path:     "/",
				}
				req.AddCookie(cookie)
			}
			response := ExecuteRequest(req, s.Router)
			assert.Equal(t, k.expected_code, response.Code)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
	badJSON := []struct {
		data          *models.User
		expected_code int
	}{
		{
			data: &models.User{
				NickName: "test",
			},
			expected_code: http.StatusBadRequest,
		},
	}
	for i, k := range badJSON {
		t.Run(fmt.Sprintln("no: ", len(data)+i+1), func(t *testing.T) {
			token, err := token.GenerateJWT(k.data)
			assert.Nil(t, err)
			cookie := &http.Cookie{
				Name:     "Token",
				Value:    token,
				HttpOnly: false,
				MaxAge:   int(time.Hour * 24 * 3),
				Path:     "/",
			}
			databuf := ConvertDatatoBuf(t, k.data)
			req, _ := http.NewRequest("PUT", "/profile/info", databuf)
			req.AddCookie(cookie)
			response := ExecuteRequest(req, s.Router)
			assert.Equal(t, k.expected_code, response.Code)
		})
	}
}

func TestEditBioError(t *testing.T) {
	log.SetOutput(io.Discard)
	s, mock := FakeNewServer(t)
	data := []struct {
		data          *models.User
		bio           *models.ProfileBio
		sql           bool
		cookie        bool
		expected_code int
	}{
		{
			data: &models.User{
				Email:    "test@test.com",
				Password: "test123",
				NickName: "testnick",
			},
			bio: &models.ProfileBio{
				NickName: "testnick",
				Info:     "test info",
			},
			expected_code: http.StatusUnauthorized,
		},
		{
			data: &models.User{
				Email:    "test2@test.com",
				Password: "test1234",
				NickName: "testnick2",
			},
			bio: &models.ProfileBio{
				NickName: "testnick2",
				Info:     "test info",
			},
			sql:           true,
			cookie:        true,
			expected_code: http.StatusInternalServerError,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			databuf := ConvertDatatoBuf(t, k.bio)
			req, _ := http.NewRequest("PUT", "/profile/info", databuf)
			if k.cookie && k.sql {
				mock.ExpectBegin()
				mock.ExpectExec(pqdb.Sql_editbio).
					WillReturnError(sql.ErrConnDone)
				mock.ExpectRollback()
				token, err := token.GenerateJWT(k.data)
				assert.Nil(t, err)
				cookie := &http.Cookie{
					Name:     "Token",
					Value:    token,
					HttpOnly: false,
					MaxAge:   int(time.Hour * 24 * 3),
					Path:     "/",
				}
				req.AddCookie(cookie)
			}
			response := ExecuteRequest(req, s.Router)
			assert.Equal(t, k.expected_code, response.Code)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
	badJSON := []struct {
		data          *models.User
		expected_code int
	}{
		{
			data: &models.User{
				NickName: "test",
			},
			expected_code: http.StatusBadRequest,
		},
	}
	for i, k := range badJSON {
		t.Run(fmt.Sprintln("no: ", len(data)+i+1), func(t *testing.T) {
			token, err := token.GenerateJWT(k.data)
			assert.Nil(t, err)
			cookie := &http.Cookie{
				Name:     "Token",
				Value:    token,
				HttpOnly: false,
				MaxAge:   int(time.Hour * 24 * 3),
				Path:     "/",
			}
			databuf := ConvertDatatoBuf(t, k.data)
			req, _ := http.NewRequest("PUT", "/profile/info", databuf)
			req.AddCookie(cookie)
			response := ExecuteRequest(req, s.Router)
			assert.Equal(t, k.expected_code, response.Code)
		})
	}
}

func TestDeleteBio(t *testing.T) {
	log.SetOutput(io.Discard)
	s, mock := FakeNewServer(t)
	data := []struct {
		data          *models.User
		bio           *models.ProfileBio
		sql           bool
		cookie        bool
		expected_code int
	}{
		{
			data: &models.User{
				Email:    "test@test.com",
				Password: "test123",
			},
			bio: &models.ProfileBio{
				NickName: "testnick",
				Info:     "test info",
			},
			sql:           true,
			cookie:        true,
			expected_code: http.StatusOK,
		},
		{
			data: &models.User{
				Email:    "test@test.com",
				Password: "test123",
				NickName: "testnick",
			},
			bio: &models.ProfileBio{
				NickName: "testnick",
				Info:     "test info",
			},
			sql:           true,
			cookie:        true,
			expected_code: http.StatusOK,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			req, _ := http.NewRequest("DELETE", "/profile/info", nil)
			if k.cookie && k.sql {
				mock.ExpectBegin()
				mock.ExpectPrepare(pqdb.Sql_deletebio).
					ExpectExec().
					WithArgs(k.data.NickName).
					WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectCommit()
				token, err := token.GenerateJWT(k.data)
				assert.Nil(t, err)
				cookie := &http.Cookie{
					Name:     "Token",
					Value:    token,
					HttpOnly: false,
					MaxAge:   int(time.Hour * 24 * 3),
					Path:     "/",
				}
				req.AddCookie(cookie)
			}
			response := ExecuteRequest(req, s.Router)
			assert.Equal(t, k.expected_code, response.Code)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
}

func TestDeleteBioError(t *testing.T) {
	log.SetOutput(io.Discard)
	s, mock := FakeNewServer(t)
	data := []struct {
		data          *models.User
		bio           *models.ProfileBio
		sql           bool
		cookie        bool
		expected_code int
	}{
		{
			data: &models.User{
				Email:    "test@test.com",
				Password: "test123",
				NickName: "testnick",
			},
			bio: &models.ProfileBio{
				NickName: "testnick",
				Info:     "test info",
			},
			expected_code: http.StatusUnauthorized,
		},
		{
			data: &models.User{
				Email:    "test2@test.com",
				Password: "test123",
				NickName: "testnick2",
			},
			bio: &models.ProfileBio{
				NickName: "testnick2",
				Info:     "test info",
			},
			sql:           true,
			cookie:        true,
			expected_code: http.StatusInternalServerError,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			req, _ := http.NewRequest("DELETE", "/profile/info", nil)
			if k.cookie && k.sql {
				mock.ExpectBegin()
				mock.ExpectPrepare(pqdb.Sql_deletebio).
					ExpectExec().
					WithArgs(k.data.NickName).
					WillReturnError(sql.ErrConnDone)
				mock.ExpectRollback()
				token, _ := token.GenerateJWT(k.data)
				cookie := &http.Cookie{
					Name:     "Token",
					Value:    token,
					HttpOnly: false,
					MaxAge:   int(time.Hour * 24 * 3),
					Path:     "/",
				}
				req.AddCookie(cookie)
			}
			response := ExecuteRequest(req, s.Router)
			assert.Equal(t, k.expected_code, response.Code)
		})
	}
}

func TestLogout(t *testing.T) {
	log.SetOutput(io.Discard)
	s, _ := FakeNewServer(t)
	data := []struct {
		data          *models.User
		expected_code int
		expected_msg  map[string]interface{}
		accept_lang   string
		cookie        bool
	}{
		{
			data: &models.User{
				Email:    "test@test.com",
				Password: "test123",
			},
			expected_code: http.StatusOK,
			expected_msg: map[string]interface{}{
				"message": "successfully logged out",
			},
			accept_lang: "en-US,en;q=0.5",
			cookie:      true,
		},
		{
			data: &models.User{
				Email:    "test@test.com",
				Password: "test123",
				NickName: "test",
			},
			expected_code: http.StatusOK,
			expected_msg: map[string]interface{}{
				"message": "başarıyla çıkış yapıldı",
			},
			accept_lang: "tr-TR,tr;q=0.9",
			cookie:      true,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			req, _ := http.NewRequest("POST", "/profile/logout", nil)
			if k.cookie {
				token, _ := token.GenerateJWT(k.data)
				cookie := &http.Cookie{
					Name:     "Token",
					Value:    token,
					HttpOnly: false,
					MaxAge:   int(time.Hour * 24 * 3),
					Path:     "/",
				}
				req.AddCookie(cookie)
				req.Header.Add("Accept-Language", k.accept_lang)
			}
			response := ExecuteRequest(req, s.Router)
			expected_body, _ := json.Marshal(&k.expected_msg)
			assert.JSONEq(t, string(expected_body), response.Body.String())
			assert.Equal(t, k.expected_code, response.Code)
		})
	}
}

func TestLogoutError(t *testing.T) {
	log.SetOutput(io.Discard)
	s, _ := FakeNewServer(t)
	data := []struct {
		data          *models.User
		expected_code int
		expected_body string
		cookie        bool
	}{
		{
			data: &models.User{
				Email:    "test1234@test.com",
				Password: "test",
			},
			expected_code: http.StatusUnauthorized,
			expected_body: "Unauthorized\n",
			cookie:        false,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			req, err := http.NewRequest("POST", "/profile/logout", nil)
			assert.Nil(t, err)
			response := ExecuteRequest(req, s.Router)
			assert.Nil(t, err)
			assert.Equal(t, k.expected_body, response.Body.String())
			assert.Equal(t, k.expected_code, response.Code)
		})
	}
}
