package handlers

import (
	"backend/models"
	Log "backend/internal/log"
	"backend/internal/param"
	"backend/token"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Home handles the request for the home page.
//
// @Summary Home
// @Description Endpoint for the home page.
// @Tags home
// @ID Home
// @Produce text/html
// @Success 200 {string} string "Home"
// @Router / [get]
func (s *Server) Home(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<h1> Welcome! </h1>`)
}

// Register handles the user registration request.
//
// @Summary Register
// @Description Endpoint for user registration.
// @Tags user
// @ID Register
// @Accept json
// @Produce json
// @Param user body models.User true "User Information"
// @Success 201 {object} render "Success Register"
// @Failure 400 {object} render "Bad Request"
// @Failure 401 {object} render "Unauthorized"
// @Failure 500 {object} render "Internal Server Error"
// @Router /register [post]
func (s *Server) Register(w http.ResponseWriter, r *http.Request) {
	user, err := ReadJSON[*models.User](r)
	if Log.Err(err) || user.ValidateRegister() {
		ErrResponse(w, http.StatusBadRequest)
		return
	}
	if err = s.DB.Postgres.CreateUser(user); Log.Err(err) {
		ErrResponse(w, http.StatusInternalServerError)
		return
	}
	msg, ok := r.Context().Value(models.Lang).(models.LangMsg)
	if !ok {
		ErrResponse(w, http.StatusUnauthorized)
		return
	}
	render := render{
		"message":  msg.Success.Register,
		"email":    user.Email,
		"nickname": user.NickName,
		"fullname": user.FullName,
	}
	Render(w, http.StatusCreated, render)
}

// Login handles the user login request.
//
// @Summary Login
// @Description Endpoint for user login.
// @Tags user
// @ID Login
// @Accept json
// @Produce json
// @Param user body models.User true "User Information"
// @Success 200 {object} render "Success Login"
// @Failure 400 {object} render "Bad Request"
// @Failure 401 {object} render "Unauthorized"
// @Failure 500 {object} render "Internal Server Error"
// @Router /login [post]
func (s *Server) Login(w http.ResponseWriter, r *http.Request) {
	user, err := ReadJSON[*models.User](r)
	if Log.Err(err) || user.ValidateLogin() {
		ErrResponse(w, http.StatusBadRequest)
		return
	}
	token, err := s.DB.Postgres.ReadUser(user)
	if Log.Err(err) {
		ErrResponse(w, http.StatusInternalServerError)
		return
	}
	SetTokenCookie(w, token, true)
	msg, ok := r.Context().Value(models.Lang).(models.LangMsg)
	if !ok {
		ErrResponse(w, http.StatusUnauthorized)
		return
	}
	render := render{
		"message": msg.Success.Login,
	}
	Render(w, 200, render)
}

// BioPublic retrieves the public bio information for a user.
//
// @Summary BioPublic
// @Description Retrieve the public bio information for a user.
// @Tags user
// @ID BioPublic
// @Param nickname path string true "User Nickname"
// @Produce json
// @Success 200 {object} render "Success BioPublic"
// @Failure 400 {object} render "Bad Request"
// @Failure 500 {object} render "Internal Server Error"
// @Router /info/{nickname} [get]
func (s *Server) BioPublic(w http.ResponseWriter, r *http.Request) {
	nickname := chi.URLParam(r, "nickname")
	if param.IsNull(nickname) {
		ErrResponse(w, http.StatusBadRequest)
		return
	}
	info, err := s.DB.Postgres.ReadBio(nickname)
	if Log.Err(err) {
		ErrResponse(w, http.StatusInternalServerError)
		return
	}
	render := render{
		"nickname": nickname,
		"info":     info,
	}
	Render(w, http.StatusOK, render)
}

// Profile retrieves the profile information for a user.
//
// @Summary Profile
// @Description Retrieve the profile information for a user.
// @Tags profile
// @ID Profile
// @Produce json
// @Security OAuth2Application
// @Success 200 {object} render "Success Profile"
// @Failure 401 {object} render "Unauthorized"
// @Failure 500 {object} render "Internal Server Error"
// @Router /profile [get]
func (s *Server) Profile(w http.ResponseWriter, r *http.Request) {
	data, err := token.ReadJWT(r)
	if Log.Err(err) {
		ErrResponse(w, http.StatusUnauthorized)
		return
	}
	info, err := s.DB.Postgres.ReadBio(data.NickName)
	if Log.Err(err) {
		ErrResponse(w, http.StatusInternalServerError)
		return
	}
	render := render{
		"email":    data.Email,
		"nickname": data.NickName,
		"fullname": data.FullName,
		"bio":      info,
	}
	Render(w, http.StatusOK, render)
}

// AddBio handles the request to add a user's bio.
//
// @Summary AddBio
// @Description Endpoint for adding a user's bio.
// @Tags /profile/info
// @ID AddBio
// @Accept json
// @Produce json
// @Param bio body models.ProfileBio true "User Bio Information"
// @Security OAuth2Application
// @Success 201 {object} render "Success AddBio"
// @Failure 400 {object} render "Bad Request"
// @Failure 401 {object} render "Unauthorized"
// @Failure 500 {object} render "Internal Server Error"
// @Router /profile/info [post]
func (s *Server) AddBio(w http.ResponseWriter, r *http.Request) {
	bio, err := ReadJSON[*models.ProfileBio](r)
	if Log.Err(err) || bio.Validate() {
		ErrResponse(w, http.StatusBadRequest)
		return
	}
	user, err := token.ReadJWT(r)
	if Log.Err(err) {
		ErrResponse(w, http.StatusUnauthorized)
		return
	}
	data := &models.ProfileBio{
		NickName: user.NickName,
		Info:     bio.Info,
	}
	if err := s.DB.Postgres.AddBio(data); Log.Err(err) {
		ErrResponse(w, http.StatusInternalServerError)
		return
	}
	msg, ok := r.Context().Value(models.Lang).(models.LangMsg)
	if !ok {
		ErrResponse(w, http.StatusUnauthorized)
		return
	}
	render := render{
		"message":  msg.Success.AddBio,
		"nickname": user.NickName,
		"info":     bio.Info,
	}
	Render(w, http.StatusCreated, render)
}

// EditBio handles the request to edit a user's bio.
//
// @Summary EditBio
// @Description Endpoint for editing a user's bio.
// @Tags /profile/info
// @ID EditBio
// @Accept json
// @Produce json
// @Param bio body models.ProfileBio true "User Bio Information"
// @Security OAuth2Application
// @Success 200 {object} render "Success EditBio"
// @Failure 400 {object} render "Bad Request"
// @Failure 401 {object} render "Unauthorized"
// @Failure 500 {object} render "Internal Server Error"
// @Router /profile/info [put]
func (s *Server) EditBio(w http.ResponseWriter, r *http.Request) {
	bio, err := ReadJSON[*models.ProfileBio](r)
	if Log.Err(err) || bio.Validate() {
		ErrResponse(w, http.StatusBadRequest)
		return
	}
	user, err := token.ReadJWT(r)
	if Log.Err(err) {
		ErrResponse(w, http.StatusUnauthorized)
		return
	}
	data := &models.ProfileBio{
		NickName: user.NickName,
		Info:     bio.Info,
	}
	if err := s.DB.Postgres.EditBio(data); Log.Err(err) {
		ErrResponse(w, http.StatusInternalServerError)
		return
	}
	msg, ok := r.Context().Value(models.Lang).(models.LangMsg)
	if !ok {
		ErrResponse(w, http.StatusUnauthorized)
		return
	}
	render := render{
		"message":  msg.Success.EditBio,
		"nickname": user.NickName,
		"new_info": bio.Info,
	}
	Render(w, http.StatusOK, render)
}

// DeleteBio handles the request to delete a user's bio.
//
// @Summary DeleteBio
// @Description Endpoint for deleting a user's bio.
// @Tags /profile/info
// @ID DeleteBio
// @Produce json
// @Security OAuth2Application
// @Success 200 {object} render "Success DeleteBio"
// @Failure 400 {object} render "Bad Request"
// @Failure 401 {object} render "Unauthorized"
// @Failure 500 {object} render "Internal Server Error"
// @Router /profile/info [delete]
func (s *Server) DeleteBio(w http.ResponseWriter, r *http.Request) {
	user, err := token.ReadJWT(r)
	if Log.Err(err) {
		ErrResponse(w, http.StatusUnauthorized)
		return
	}
	if err := s.DB.Postgres.DeleteBio(user.NickName); Log.Err(err) {
		ErrResponse(w, http.StatusInternalServerError)
		return
	}
	msg, ok := r.Context().Value(models.Lang).(models.LangMsg)
	if !ok {
		ErrResponse(w, http.StatusUnauthorized)
		return
	}
	render := render{
		"message":  msg.Success.DeleteBio,
		"nickname": user.NickName,
	}
	Render(w, http.StatusOK, render)
}

// Logout handles the user logout request.
//
// @Summary Logout
// @Description Endpoint for user logout.
// @Tags profile
// @ID Logout
// @Produce json
// @Security OAuth2Application
// @Success 200 {object} render "Success Logout"
// @Failure 401 {object} render "Unauthorized"
// @Router /profile/logout [post]
func (s *Server) Logout(w http.ResponseWriter, r *http.Request) {
	SetTokenCookie(w, "", false)
	msg, ok := r.Context().Value(models.Lang).(models.LangMsg)
	if !ok {
		ErrResponse(w, http.StatusUnauthorized)
		return
	}
	render := render{
		"message": msg.Success.Logout,
	}
	Render(w, http.StatusOK, render)
}
