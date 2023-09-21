package handlers

import (
	"backend/api/middlewares"
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
	"github.com/brianvoe/gofakeit/v6"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	chirender "github.com/go-chi/render"
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
)

func executeRequest(req *http.Request, s *chi.Mux) *httptest.ResponseRecorder {
	log.SetOutput(io.Discard)
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	return rr
}

func setupRouters(s *Server) *chi.Mux {
	r := chi.NewRouter()
	// Middlewares
	r.Use(
		middleware.RequestID,
		middleware.RealIP,
		middleware.Logger,
		middleware.Recoverer,
		chirender.SetContentType(chirender.ContentTypeJSON),
		middlewares.Languages,
	)
	r.Get("/", s.Home)
	r.Post("/register", s.Register)
	r.Post("/login", s.Login)
	r.Get("/info/{nickname}", s.BioPublic)
	// Usersonly Handlers
	userRouters := func() chi.Router {
		r := chi.NewRouter()
		r.Use(middlewares.UsersOnly)
		r.Get("/", s.Profile)
		// user info(bio)
		r.Post("/info", s.AddBio)
		r.Put("/info", s.EditBio)
		r.Delete("/info", s.DeleteBio)

		r.Post("/logout", s.Logout)
		return r
	}
	r.Mount("/profile", userRouters())
	return r
}

func fakeNewServer(t *testing.T) (*chi.Mux, *Server, sqlmock.Sqlmock) {
	log.SetOutput(io.Discard)
	d, m := newMock(t)
	s := &Server{
		DB: &database.DB{
			Postgres: &pqdb.Server{
				Client: d,
			},
		},
	}
	r := setupRouters(s)
	return r, s, m
}

func newMock(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	log.SetOutput(io.Discard)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Errorf("error in mock database connection: %s", err)
	}
	return db, mock
}

func convertDatatoBuf(t *testing.T, data any) *bytes.Buffer {
	log.SetOutput(io.Discard)
	databuf := new(bytes.Buffer)
	if err := json.NewEncoder(databuf).Encode(data); err != nil {
		t.Errorf("error when convert json to buf %v", err)
	}
	return databuf
}

func fakeGenerateJWT(t *testing.T, user *models.User, signingkey []byte,
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
	r, _, _ := fakeNewServer(t)
	req, err := http.NewRequest(http.MethodGet, "/", nil)
	assert.Nil(t, err)
	response := executeRequest(req, r)
	assert.Equal(t, http.StatusOK, response.Code)
}

func TestRegister(t *testing.T) {
	log.SetOutput(io.Discard)
	r, _, mock := fakeNewServer(t)
	data := []struct {
		data         *models.User
		method       string
		url          string
		expectedCode int
	}{
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
				NickName: gofakeit.Username(),
				FullName: gofakeit.Name(),
			},
			method:       "POST",
			url:          "/register",
			expectedCode: http.StatusCreated,
		},
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
				NickName: gofakeit.Username(),
				FullName: gofakeit.Name(),
			},
			method:       "POST",
			url:          "/register",
			expectedCode: http.StatusCreated,
		},
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
				NickName: gofakeit.Username(),
				FullName: gofakeit.Name(),
			},
			method:       "POST",
			url:          "/register",
			expectedCode: http.StatusCreated,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			mock.ExpectBegin()
			mock.ExpectExec(pqdb.CreateUser).
				WillReturnResult(sqlmock.NewResult(1, 1))
			mock.ExpectCommit()
			databuf := convertDatatoBuf(t, k.data)
			req, err := http.NewRequest(k.method, k.url, databuf)
			assert.Nil(t, err)
			response := executeRequest(req, r)
			assert.Equal(t, k.expectedCode, response.Code)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
}

func TestRegisterError(t *testing.T) {
	log.SetOutput(io.Discard)
	r, s, mock := fakeNewServer(t)
	data := []struct {
		data         *models.User
		sql          bool
		method       string
		url          string
		expectedCode int
	}{
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
				NickName: gofakeit.Username(),
				FullName: gofakeit.Name(),
			},
			sql:          true,
			method:       "POST",
			url:          "/register",
			expectedCode: http.StatusInternalServerError,
		},
		{
			data: &models.User{
				Password: gofakeit.Password(true, true, true, true, false, 10),
			},
			method:       "POST",
			url:          "/register",
			expectedCode: http.StatusBadRequest,
		},
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
			},
			method:       "POST",
			url:          "/register",
			expectedCode: http.StatusBadRequest,
		},
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 100),
				NickName: gofakeit.Username(),
				FullName: gofakeit.Name(),
			},
			method:       "POST",
			url:          "/register",
			expectedCode: http.StatusInternalServerError,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			//test registered email
			if k.sql {
				mock.ExpectBegin()
				mock.ExpectExec(pqdb.CreateUser).
					WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectCommit()
				err := s.DB.Postgres.CreateUser(k.data)
				assert.Nil(t, err)
			}
			databuf := convertDatatoBuf(t, k.data)
			req, err := http.NewRequest(k.method, k.url, databuf)
			assert.Nil(t, err)
			response := executeRequest(req, r)
			assert.Equal(t, k.expectedCode, response.Code)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
	badJSON := []struct {
		data         any
		method       string
		url          string
		expectedCode int
	}{
		{
			data:         gofakeit.Name(),
			method:       "POST",
			url:          "/register",
			expectedCode: http.StatusBadRequest,
		},
		{
			data: &models.ProfileBio{
				NickName: gofakeit.Username(),
			},
			method:       "POST",
			url:          "/register",
			expectedCode: http.StatusBadRequest,
		},
	}
	for i, k := range badJSON {
		t.Run(fmt.Sprintln("no: ", len(data)+i+1), func(t *testing.T) {
			databuf := convertDatatoBuf(t, k.data)
			req, err := http.NewRequest(k.method, k.url, databuf)
			assert.Nil(t, err)
			response := executeRequest(req, r)
			assert.Equal(t, k.expectedCode, response.Code)
		})
	}
}

func TestLogin(t *testing.T) {
	log.SetOutput(io.Discard)
	r, _, mock := fakeNewServer(t)
	data := []struct {
		data         *models.User
		method       string
		url          string
		expectedCode int
	}{
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
			},
			method:       "POST",
			url:          "/login",
			expectedCode: http.StatusOK,
		},
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
				NickName: gofakeit.Username(),
			},
			method:       "POST",
			url:          "/login",
			expectedCode: http.StatusOK,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			pwd, _ := pqdb.HashPassword(k.data.Password)
			rows := sqlmock.NewRows([]string{"Email", "Pwd", "NickName", "FullName"}).
				AddRow(k.data.Email, pwd, k.data.NickName, k.data.FullName)
			mock.ExpectBegin()
			mock.ExpectQuery(pqdb.ReadUser).
				WithArgs(k.data.Email).
				WillReturnRows(rows)
			mock.ExpectCommit()
			databuf := convertDatatoBuf(t, k.data)
			req, _ := http.NewRequest(k.method, k.url, databuf)
			response := executeRequest(req, r)
			assert.Equal(t, k.expectedCode, response.Code)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
}

func TestLoginError(t *testing.T) {
	log.SetOutput(io.Discard)
	r, s, mock := fakeNewServer(t)
	data := []struct {
		data         *models.User
		sql          bool
		method       string
		url          string
		expectedCode int
	}{
		{
			data: &models.User{
				Password: gofakeit.Password(true, true, true, true, false, 10),
				NickName: gofakeit.Username(),
			},
			method:       "POST",
			url:          "/login",
			expectedCode: http.StatusBadRequest,
		},
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
			},
			sql:          true,
			method:       "POST",
			url:          "/login",
			expectedCode: http.StatusInternalServerError,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			//test wrong password
			if k.sql {
				mock.ExpectBegin()
				mock.ExpectExec(pqdb.CreateUser).
					WillReturnResult(sqlmock.NewResult(1, 1))
				mock.ExpectCommit()
				err := s.DB.Postgres.CreateUser(k.data)
				assert.Nil(t, err)
				pwd, _ := pqdb.HashPassword(k.data.Password + "fails.")
				rows := sqlmock.NewRows([]string{"Email", "Pwd", "NickName", "FullName"}).
					AddRow(k.data.Email, pwd, k.data.NickName, k.data.FullName)
				mock.ExpectBegin()
				mock.ExpectQuery(pqdb.ReadUser).
					WithArgs(k.data.Email).
					WillReturnRows(rows)
				mock.ExpectRollback()
			}
			databuf := convertDatatoBuf(t, k.data)
			req, _ := http.NewRequest("POST", "/login", databuf)
			response := executeRequest(req, r)
			assert.Equal(t, k.expectedCode, response.Code)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
	badJSON := []struct {
		data         any
		method       string
		url          string
		expectedCode int
	}{
		{
			data:         gofakeit.Name(),
			method:       "POST",
			url:          "/login",
			expectedCode: http.StatusBadRequest,
		},
		{
			data: &models.ProfileBio{
				NickName: gofakeit.Username(),
			},
			method:       "POST",
			url:          "/login",
			expectedCode: http.StatusBadRequest,
		},
	}
	for i, k := range badJSON {
		t.Run(fmt.Sprintln("no: ", len(data)+i+1), func(t *testing.T) {
			databuf := convertDatatoBuf(t, k.data)
			req, _ := http.NewRequest("POST", "/login", databuf)
			response := executeRequest(req, r)
			assert.Equal(t, k.expectedCode, response.Code)
		})
	}
}

func TestBioPublic(t *testing.T) {
	log.SetOutput(io.Discard)
	r, _, mock := fakeNewServer(t)
	data := []struct {
		data         *models.ProfileBio
		method       string
		url          string
		expectedCode int
	}{
		{
			data: &models.ProfileBio{
				NickName: gofakeit.Username(),
				Info:     gofakeit.LoremIpsumWord(),
			},
			method:       "GET",
			url:          "/info",
			expectedCode: http.StatusOK,
		},
		{
			data: &models.ProfileBio{
				NickName: gofakeit.Username(),
				Info:     gofakeit.LoremIpsumWord(),
			},
			method:       "GET",
			url:          "/info",
			expectedCode: http.StatusOK,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			rows := sqlmock.NewRows([]string{"Info"}).
				AddRow(k.data.Info)
			mock.ExpectBegin()
			mock.ExpectQuery(pqdb.ReadBio).
				WithArgs(k.data.NickName).
				WillReturnRows(rows)
			mock.ExpectCommit()
			url := fmt.Sprintf("%s/%s", k.url, k.data.NickName)
			req, _ := http.NewRequest(k.method, url, nil)
			response := executeRequest(req, r)
			assert.Equal(t, k.expectedCode, response.Code)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
}

func TestBioPublicError(t *testing.T) {
	log.SetOutput(io.Discard)
	r, _, mock := fakeNewServer(t)
	data := []struct {
		data         *models.ProfileBio
		sql          bool
		method       string
		url          string
		expectedCode int
	}{
		{
			data: &models.ProfileBio{
				NickName: "",
				Info:     gofakeit.LoremIpsumWord(),
			},
			method:       "GET",
			url:          "/info",
			expectedCode: http.StatusNotFound,
		},
		{
			data: &models.ProfileBio{
				Info: gofakeit.LoremIpsumWord(),
			},
			method:       "GET",
			url:          "/info",
			expectedCode: http.StatusNotFound,
		},
		{
			data: &models.ProfileBio{
				NickName: gofakeit.Username(),
				Info:     gofakeit.LoremIpsumWord(),
			},
			sql:          true,
			method:       "GET",
			url:          "/info",
			expectedCode: http.StatusInternalServerError,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			if k.sql {
				mock.ExpectBegin()
				mock.ExpectQuery(pqdb.ReadBio).
					WithArgs(k.data.NickName).
					WillReturnError(sql.ErrConnDone)
				mock.ExpectRollback()
			}
			url := fmt.Sprintf("%s/%s", k.url, k.data.NickName)
			req, _ := http.NewRequest(k.method, url, nil)
			response := executeRequest(req, r)
			assert.Equal(t, k.expectedCode, response.Code)
			assert.Nil(t, mock.ExpectationsWereMet())

		})
	}
}

func TestProfile(t *testing.T) {
	log.SetOutput(io.Discard)
	r, _, mock := fakeNewServer(t)
	data := []struct {
		data         *models.User
		bio          *models.ProfileBio
		cookie       bool
		method       string
		url          string
		expectedCode int
	}{
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
			},
			bio: &models.ProfileBio{
				NickName: gofakeit.Username(),
				Info:     gofakeit.LoremIpsumWord(),
			},
			cookie:       true,
			method:       "GET",
			url:          "/profile",
			expectedCode: http.StatusOK,
		},
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
				NickName: gofakeit.Username(),
			},
			bio: &models.ProfileBio{
				NickName: gofakeit.Username(),
				Info:     gofakeit.LoremIpsumWord(),
			},
			cookie:       true,
			method:       "GET",
			url:          "/profile",
			expectedCode: http.StatusOK,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			rows := sqlmock.NewRows([]string{"Info"}).
				AddRow(k.bio.Info)
			mock.ExpectBegin()
			mock.ExpectQuery(pqdb.ReadBio).
				WithArgs(k.data.NickName).
				WillReturnRows(rows)
			mock.ExpectCommit()
			req, _ := http.NewRequest(k.method, k.url, nil)
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
			response := executeRequest(req, r)
			assert.Equal(t, k.expectedCode, response.Code)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
}

func TestProfileError(t *testing.T) {
	log.SetOutput(io.Discard)
	r, _, mock := fakeNewServer(t)
	data := []struct {
		data         *models.User
		bio          *models.ProfileBio
		sql          bool
		cookie       bool
		method       string
		url          string
		expectedCode int
	}{
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
				NickName: gofakeit.Username(),
			},
			bio: &models.ProfileBio{
				NickName: gofakeit.Username(),
				Info:     gofakeit.LoremIpsumWord(),
			},
			method:       "GET",
			url:          "/profile",
			expectedCode: http.StatusUnauthorized,
		},
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
				NickName: gofakeit.Username(),
			},
			bio: &models.ProfileBio{
				NickName: gofakeit.Username(),
				Info:     gofakeit.LoremIpsumWord(),
			},
			sql:          true,
			cookie:       true,
			method:       "GET",
			url:          "/profile",
			expectedCode: http.StatusInternalServerError,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			req, _ := http.NewRequest(k.method, k.url, nil)
			if k.cookie && k.sql {
				mock.ExpectBegin()
				mock.ExpectQuery(pqdb.ReadBio).
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
			response := executeRequest(req, r)
			assert.Equal(t, k.expectedCode, response.Code)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
	Unauthorized := []struct {
		data       *models.User
		signingkey []byte
		method     *jwt.SigningMethodHMAC
		time       int64
		urlMethod  string
		url        string
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
			urlMethod:  "GET",
			url:        "/profile",
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
			urlMethod:  "GET",
			url:        "/profile",
			expected:   http.StatusUnauthorized,
		},
	}
	for i, k := range Unauthorized {
		t.Run(fmt.Sprintln("no: ", len(data)+i+1), func(t *testing.T) {
			token, _ := fakeGenerateJWT(t, k.data, k.signingkey, k.method, k.time)
			req, _ := http.NewRequest(k.urlMethod, k.url, nil)
			cookie := &http.Cookie{
				Name:     "Token",
				Value:    token,
				HttpOnly: false,
				MaxAge:   int(time.Hour * 24 * 3),
				Path:     "/",
			}
			req.AddCookie(cookie)
			response := executeRequest(req, r)
			assert.Equal(t, k.expected, response.Code)
		})
	}
}

func TestAddBio(t *testing.T) {
	log.SetOutput(io.Discard)
	r, _, mock := fakeNewServer(t)
	data := []struct {
		data         *models.User
		bio          *models.ProfileBio
		cookie       bool
		method       string
		url          string
		expectedCode int
	}{
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
			},
			bio: &models.ProfileBio{
				NickName: gofakeit.Username(),
				Info:     gofakeit.LoremIpsumWord(),
			},
			cookie:       true,
			method:       "POST",
			url:          "/profile/info",
			expectedCode: http.StatusCreated,
		},
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
				NickName: gofakeit.Username(),
			},
			bio: &models.ProfileBio{
				NickName: gofakeit.Username(),
				Info:     gofakeit.LoremIpsumWord(),
			},
			cookie:       true,
			method:       "POST",
			url:          "/profile/info",
			expectedCode: http.StatusCreated,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			mock.ExpectBegin()
			mock.ExpectExec(pqdb.AddBio).
				WillReturnResult(sqlmock.NewResult(1, 1))
			mock.ExpectCommit()
			databuf := convertDatatoBuf(t, k.bio)
			req, _ := http.NewRequest(k.method, k.url, databuf)
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
			response := executeRequest(req, r)
			assert.Equal(t, k.expectedCode, response.Code)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
}

func TestAddBioError(t *testing.T) {
	log.SetOutput(io.Discard)
	r, _, mock := fakeNewServer(t)
	data := []struct {
		data         *models.User
		bio          *models.ProfileBio
		sql          bool
		cookie       bool
		method       string
		url          string
		expectedCode int
	}{
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
				NickName: gofakeit.Username(),
			},
			bio: &models.ProfileBio{
				NickName: gofakeit.Username(),
				Info:     gofakeit.LoremIpsumWord(),
			},
			method:       "POST",
			url:          "/profile/info",
			expectedCode: http.StatusUnauthorized,
		},
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
				NickName: gofakeit.Username(),
			},
			bio: &models.ProfileBio{
				NickName: gofakeit.Username(),
				Info:     gofakeit.LoremIpsumWord(),
			},
			method:       "POST",
			url:          "/profile/info",
			expectedCode: http.StatusUnauthorized,
		},
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
				NickName: gofakeit.Username(),
			},
			bio: &models.ProfileBio{
				NickName: gofakeit.Username(),
				Info:     gofakeit.LoremIpsumWord(),
			},
			sql:          true,
			cookie:       true,
			method:       "POST",
			url:          "/profile/info",
			expectedCode: http.StatusInternalServerError,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			databuf := convertDatatoBuf(t, k.bio)
			req, _ := http.NewRequest(k.method, k.url, databuf)
			if k.cookie && k.sql {
				mock.ExpectBegin()
				mock.ExpectExec(pqdb.AddBio).
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
			response := executeRequest(req, r)
			assert.Equal(t, k.expectedCode, response.Code)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
	badJSON := []struct {
		data         *models.User
		method       string
		url          string
		expectedCode int
	}{
		{
			data: &models.User{
				NickName: gofakeit.Username(),
			},
			method:       "POST",
			url:          "/profile/info",
			expectedCode: http.StatusBadRequest,
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
			databuf := convertDatatoBuf(t, k.data)
			req, _ := http.NewRequest(k.method, k.url, databuf)
			req.AddCookie(cookie)
			response := executeRequest(req, r)
			assert.Equal(t, k.expectedCode, response.Code)
		})
	}
}

func TestEditBio(t *testing.T) {
	log.SetOutput(io.Discard)
	r, _, mock := fakeNewServer(t)
	data := []struct {
		data         *models.User
		bio          *models.ProfileBio
		cookie       bool
		method       string
		url          string
		expectedCode int
	}{
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
			},
			bio: &models.ProfileBio{
				NickName: gofakeit.Username(),
				Info:     gofakeit.LoremIpsumWord(),
			},
			cookie:       true,
			method:       "PUT",
			url:          "/profile/info",
			expectedCode: http.StatusOK,
		},
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
				NickName: gofakeit.Username(),
			},
			bio: &models.ProfileBio{
				NickName: gofakeit.Username(),
				Info:     gofakeit.LoremIpsumWord(),
			},
			cookie:       true,
			method:       "PUT",
			url:          "/profile/info",
			expectedCode: http.StatusOK,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			mock.ExpectBegin()
			mock.ExpectExec(pqdb.EditBio).
				WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectCommit()
			databuf := convertDatatoBuf(t, k.bio)
			req, _ := http.NewRequest(k.method, k.url, databuf)
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
			response := executeRequest(req, r)
			assert.Equal(t, k.expectedCode, response.Code)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
}

func TestEditBioError(t *testing.T) {
	log.SetOutput(io.Discard)
	r, _, mock := fakeNewServer(t)
	data := []struct {
		data         *models.User
		bio          *models.ProfileBio
		sql          bool
		cookie       bool
		method       string
		url          string
		expectedCode int
	}{
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
				NickName: gofakeit.Username(),
			},
			bio: &models.ProfileBio{
				NickName: gofakeit.Username(),
				Info:     gofakeit.LoremIpsumWord(),
			},
			method:       "PUT",
			url:          "/profile/info",
			expectedCode: http.StatusUnauthorized,
		},
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
				NickName: gofakeit.Username(),
			},
			bio: &models.ProfileBio{
				NickName: gofakeit.Username(),
				Info:     gofakeit.LoremIpsumWord(),
			},
			sql:          true,
			cookie:       true,
			method:       "PUT",
			url:          "/profile/info",
			expectedCode: http.StatusInternalServerError,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			databuf := convertDatatoBuf(t, k.bio)
			req, _ := http.NewRequest(k.method, k.url, databuf)
			if k.cookie && k.sql {
				mock.ExpectBegin()
				mock.ExpectExec(pqdb.EditBio).
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
			response := executeRequest(req, r)
			assert.Equal(t, k.expectedCode, response.Code)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
	badJSON := []struct {
		data         *models.User
		method       string
		url          string
		expectedCode int
	}{
		{
			data: &models.User{
				NickName: gofakeit.Username(),
			},
			method:       "PUT",
			url:          "/profile/info",
			expectedCode: http.StatusBadRequest,
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
			databuf := convertDatatoBuf(t, k.data)
			req, _ := http.NewRequest(k.method, k.url, databuf)
			req.AddCookie(cookie)
			response := executeRequest(req, r)
			assert.Equal(t, k.expectedCode, response.Code)
		})
	}
}

func TestDeleteBio(t *testing.T) {
	log.SetOutput(io.Discard)
	r, _, mock := fakeNewServer(t)
	data := []struct {
		data         *models.User
		bio          *models.ProfileBio
		sql          bool
		cookie       bool
		method       string
		url          string
		expectedCode int
	}{
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
			},
			bio: &models.ProfileBio{
				NickName: gofakeit.Username(),
				Info:     gofakeit.LoremIpsumWord(),
			},
			sql:          true,
			cookie:       true,
			method:       "DELETE",
			url:          "/profile/info",
			expectedCode: http.StatusOK,
		},
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
				NickName: gofakeit.Username(),
			},
			bio: &models.ProfileBio{
				NickName: gofakeit.Username(),
				Info:     gofakeit.LoremIpsumWord(),
			},
			sql:          true,
			cookie:       true,
			method:       "DELETE",
			url:          "/profile/info",
			expectedCode: http.StatusOK,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			req, _ := http.NewRequest(k.method, k.url, nil)
			if k.cookie && k.sql {
				mock.ExpectBegin()
				mock.ExpectPrepare(pqdb.DeleteBio).
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
			response := executeRequest(req, r)
			assert.Equal(t, k.expectedCode, response.Code)
			assert.Nil(t, mock.ExpectationsWereMet())
		})
	}
}

func TestDeleteBioError(t *testing.T) {
	log.SetOutput(io.Discard)
	r, _, mock := fakeNewServer(t)
	data := []struct {
		data         *models.User
		bio          *models.ProfileBio
		sql          bool
		cookie       bool
		method       string
		url          string
		expectedCode int
	}{
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
				NickName: gofakeit.Username(),
			},
			bio: &models.ProfileBio{
				NickName: gofakeit.Username(),
				Info:     gofakeit.LoremIpsumWord(),
			},
			method:       "DELETE",
			url:          "/profile/info",
			expectedCode: http.StatusUnauthorized,
		},
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
				NickName: gofakeit.Username(),
			},
			bio: &models.ProfileBio{
				NickName: gofakeit.Username(),
				Info:     gofakeit.LoremIpsumWord(),
			},
			sql:          true,
			cookie:       true,
			method:       "DELETE",
			url:          "/profile/info",
			expectedCode: http.StatusInternalServerError,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			req, _ := http.NewRequest(k.method, k.url, nil)
			if k.cookie && k.sql {
				mock.ExpectBegin()
				mock.ExpectPrepare(pqdb.DeleteBio).
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
			response := executeRequest(req, r)
			assert.Equal(t, k.expectedCode, response.Code)
		})
	}
}

func TestLogout(t *testing.T) {
	log.SetOutput(io.Discard)
	r, _, _ := fakeNewServer(t)
	data := []struct {
		data         *models.User
		expectedMsg  map[string]interface{}
		acceptLang   string
		cookie       bool
		method       string
		url          string
		expectedCode int
	}{
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
			},
			expectedMsg: map[string]interface{}{
				"message": "successfully logged out",
			},
			acceptLang:   "en-US,en;q=0.5",
			cookie:       true,
			method:       "POST",
			url:          "/profile/logout",
			expectedCode: http.StatusOK,
		},
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
				NickName: gofakeit.Username(),
			},
			expectedMsg: map[string]interface{}{
				"message": "başarıyla çıkış yapıldı",
			},
			acceptLang:   "tr-TR,tr;q=0.9",
			cookie:       true,
			method:       "POST",
			url:          "/profile/logout",
			expectedCode: http.StatusOK,
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			req, _ := http.NewRequest(k.method, k.url, nil)
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
				req.Header.Add("Accept-Language", k.acceptLang)
			}
			response := executeRequest(req, r)
			expectedBody, _ := json.Marshal(&k.expectedMsg)
			assert.JSONEq(t, string(expectedBody), response.Body.String())
			assert.Equal(t, k.expectedCode, response.Code)
		})
	}
}

func TestLogoutError(t *testing.T) {
	log.SetOutput(io.Discard)
	r, _, _ := fakeNewServer(t)
	data := []struct {
		data         *models.User
		cookie       bool
		method       string
		url          string
		expectedBody string
		expectedCode int
	}{
		{
			data: &models.User{
				Email:    gofakeit.Email(),
				Password: gofakeit.Password(true, true, true, true, false, 10),
			},
			cookie:       false,
			method:       "POST",
			url:          "/profile/logout",
			expectedCode: http.StatusUnauthorized,
			expectedBody: "Unauthorized\n",
		},
	}
	for i, k := range data {
		t.Run(fmt.Sprintln("no: ", i+1), func(t *testing.T) {
			req, err := http.NewRequest("POST", "/profile/logout", nil)
			assert.Nil(t, err)
			response := executeRequest(req, r)
			assert.Nil(t, err)
			assert.Equal(t, k.expectedBody, response.Body.String())
			assert.Equal(t, k.expectedCode, response.Code)
		})
	}
}
