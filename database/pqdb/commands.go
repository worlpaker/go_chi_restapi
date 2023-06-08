package pqdb

import (
	"backend/models"
	Log "backend/pkg/helpers/log"
	"backend/pkg/token"
	"context"
	"database/sql"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// SQL Command Functions

// CreateUser creates a new user in the SQL database.
func (s *Server) CreateUser(user *models.User) error {
	tx, err := s.Client.Begin()
	if Log.Err(err) {
		return err
	}
	defer func() { HandleTransaction(tx, &err) }()
	hashed_Pwd, err := HashPassword(user.Password)
	if Log.Err(err) {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = tx.ExecContext(ctx, CreateUser,
		user.Email, hashed_Pwd, user.NickName, user.FullName)
	return err
}

// ReadUser reads user information from the SQL database and returns a JWT token.
func (s *Server) ReadUser(user *models.User) (string, error) {
	var dbuser models.User
	tx, err := s.Client.Begin()
	if Log.Err(err) {
		return "", err
	}
	defer HandleTransaction(tx, &err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = tx.QueryRowContext(ctx, ReadUser, user.Email).Scan(
		&dbuser.Email, &dbuser.Password, &dbuser.NickName, &dbuser.FullName); Log.Err(err) {
		return "", err
	}
	if err = bcrypt.CompareHashAndPassword([]byte(dbuser.Password), []byte(user.Password)); Log.Err(err) {
		return "", ErrIncorrectPassword
	}
	t, err := token.GenerateJWT(&dbuser)
	if Log.Err(err) {
		return "", err
	}
	return t, nil
}

// AddBio adds a new profile bio to the SQL database.
func (s *Server) AddBio(user *models.ProfileBio) error {
	tx, err := s.Client.Begin()
	if Log.Err(err) {
		return err
	}
	defer HandleTransaction(tx, &err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = tx.ExecContext(ctx, AddBio, user.NickName, user.Info)
	return err
}

// ReadBio retrieves the profile bio information from the SQL database based on the provided nickname.
func (s *Server) ReadBio(nickname string) (string, error) {
	var dbuser models.ProfileBio
	tx, err := s.Client.Begin()
	if Log.Err(err) {
		return "", err
	}
	defer HandleTransaction(tx, &err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = tx.QueryRowContext(ctx, ReadBio, nickname).
		Scan(&dbuser.Info); Log.Err(err) && err != sql.ErrNoRows {
		return "", err
	}
	return dbuser.Info, nil
}

// EditBio updates the profile bio in the SQL database with the provided information.
func (s *Server) EditBio(user *models.ProfileBio) error {
	tx, err := s.Client.Begin()
	if Log.Err(err) {
		return err
	}
	defer HandleTransaction(tx, &err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = tx.ExecContext(ctx, EditBio, user.NickName, user.Info)
	return err
}

// DeleteBio deletes the profile bio from the SQL database based on the provided nickname.
func (s *Server) DeleteBio(nickname string) error {
	//example of using prepare context
	//Why? - When you expect to execute the same SQL repeatedly.
	//typically containing placeholders but with no actual parameter values
	//A prepared statement is SQL that is parsed and saved by the DBMS,
	//typically containing placeholders but with no actual parameter values.
	//Later, the statement can be executed with a set of parameter values.
	//see: https://go.dev/doc/database/prepared-statements
	tx, err := s.Client.Begin()
	if Log.Err(err) {
		return err
	}
	defer HandleTransaction(tx, &err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stmt, err := tx.PrepareContext(ctx, DeleteBio)
	if Log.Err(err) {
		return err
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, nickname)
	return err
}
