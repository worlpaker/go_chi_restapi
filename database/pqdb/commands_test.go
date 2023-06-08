package pqdb

import (
	"backend/models"
	"database/sql"
	"errors"
	"io"
	"log"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
)

func FakeNewAuth(t *testing.T) (*Server, sqlmock.Sqlmock) {
	log.SetOutput(io.Discard)
	d, m := NewMock(t)
	s := &Server{
		Client: d,
	}
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

func TestSQL_CreateUser(t *testing.T) {
	log.SetOutput(io.Discard)
	s, mock := FakeNewAuth(t)
	test_fullname := "test and test"
	data := &models.User{
		Email:    "test@test.com",
		Password: "test123",
		NickName: "test",
		FullName: &test_fullname,
	}
	mock.ExpectBegin()
	mock.ExpectExec(Sql_createuser).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	err := s.SQL_CreateUser(data)
	assert.Nil(t, err)
	// we make sure that all expectations were met
	assert.Nil(t, mock.ExpectationsWereMet())
}

func TestSQL_CreateUserError(t *testing.T) {
	log.SetOutput(io.Discard)
	s, mock := FakeNewAuth(t)
	test_fullname := "test and test"
	data := &models.User{
		Email:    "test@test.com",
		Password: "test123",
		NickName: "test",
		FullName: &test_fullname,
	}
	mock.ExpectBegin()
	mock.ExpectExec(Sql_createuser).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()
	err := s.SQL_CreateUser(data)
	assert.Error(t, err)
	// we make sure that all expectations were met
	assert.Nil(t, mock.ExpectationsWereMet())
}

func TestSQL_ReadUser(t *testing.T) {
	log.SetOutput(io.Discard)
	s, mock := FakeNewAuth(t)
	test_fullname := "test and test"
	data := &models.User{
		Email:    "test@test.com",
		Password: "test123",
		NickName: "test",
		FullName: &test_fullname,
	}
	hashed_Pwd, err := HashPassword(data.Password)
	assert.Nil(t, err)
	rows := sqlmock.NewRows([]string{"Email", "Pwd", "NickName", "FullName"}).
		AddRow(data.Email, hashed_Pwd, data.NickName, data.FullName)
	mock.ExpectBegin()
	mock.ExpectQuery(Sql_readuser).
		WithArgs(data.Email).
		WillReturnRows(rows)
	mock.ExpectCommit()
	_, err = s.SQL_ReadUser(data)
	assert.Nil(t, err)
	assert.Nil(t, mock.ExpectationsWereMet())
}

func TestSQL_ReadUserError(t *testing.T) {
	log.SetOutput(io.Discard)
	s, mock := FakeNewAuth(t)
	test_fullname := "test and test"
	data := &models.User{
		Email:    "test@test.com",
		Password: "test123",
		NickName: "test",
		FullName: &test_fullname,
	}
	mock.ExpectBegin()
	mock.ExpectQuery(Sql_readuser).
		WithArgs(data.Email).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()
	_, err := s.SQL_ReadUser(data)
	assert.Error(t, err)
	assert.Nil(t, mock.ExpectationsWereMet())
}

func TestSQL_AddBio(t *testing.T) {
	log.SetOutput(io.Discard)
	s, mock := FakeNewAuth(t)
	data := &models.ProfileBio{
		NickName: "test",
		Info:     "test info",
	}
	mock.ExpectBegin()
	mock.ExpectExec(Sql_addbio).
		WithArgs(data.NickName, data.Info).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	err := s.SQL_AddBio(data)
	assert.Nil(t, err)
	assert.Nil(t, mock.ExpectationsWereMet())
}

func TestSQL_AddBioError(t *testing.T) {
	log.SetOutput(io.Discard)
	s, mock := FakeNewAuth(t)
	data := &models.ProfileBio{
		NickName: "test",
		Info:     "test info",
	}
	mock.ExpectBegin()
	mock.ExpectExec(Sql_addbio).
		WithArgs(data.NickName, data.Info).
		WillReturnError(sql.ErrConnDone)
	mock.ExpectRollback()
	err := s.SQL_AddBio(data)
	assert.Error(t, err)
	assert.Nil(t, mock.ExpectationsWereMet())
}

func TestSQL_ReadBio(t *testing.T) {
	log.SetOutput(io.Discard)
	s, mock := FakeNewAuth(t)
	data := models.ProfileBio{
		NickName: "test",
		Info:     "test info",
	}
	rows := sqlmock.NewRows([]string{"Info"}).
		AddRow(data.Info)
	mock.ExpectBegin()
	mock.ExpectQuery(Sql_readbio).
		WithArgs(data.NickName).
		WillReturnRows(rows)
	mock.ExpectCommit()
	_, err := s.SQL_ReadBio(data.NickName)
	assert.Nil(t, err)
	assert.Nil(t, mock.ExpectationsWereMet())
}

func TestSQL_ReadBioError(t *testing.T) {
	log.SetOutput(io.Discard)
	s, mock := FakeNewAuth(t)
	data := &models.ProfileBio{
		NickName: "test",
		Info:     "test info",
	}
	mock.ExpectBegin()
	mock.ExpectQuery(Sql_readbio).
		WithArgs(data.NickName).
		WillReturnError(errors.New("new error"))
	mock.ExpectRollback()
	_, err := s.SQL_ReadBio(data.NickName)
	assert.Error(t, err)
	assert.Nil(t, mock.ExpectationsWereMet())
	//test if no rows
	mock.ExpectBegin()
	mock.ExpectQuery(Sql_readbio).
		WithArgs(data.NickName).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()
	_, err = s.SQL_ReadBio(data.NickName)
	assert.Nil(t, err)
	assert.Nil(t, mock.ExpectationsWereMet())
}

func TestSQL_EditBio(t *testing.T) {
	log.SetOutput(io.Discard)
	s, mock := FakeNewAuth(t)
	data := &models.ProfileBio{
		NickName: "test",
		Info:     "test info",
	}
	mock.ExpectBegin()
	mock.ExpectExec(Sql_editbio).
		WithArgs(data.NickName, data.Info).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	err := s.SQL_EditBio(data)
	assert.Nil(t, err)
	assert.Nil(t, mock.ExpectationsWereMet())
}

func TestSQL_EditBioError(t *testing.T) {
	log.SetOutput(io.Discard)
	s, mock := FakeNewAuth(t)
	data := &models.ProfileBio{
		NickName: "test",
		Info:     "test info",
	}
	mock.ExpectBegin()
	mock.ExpectExec(Sql_editbio).
		WithArgs(data.NickName, data.Info).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()
	err := s.SQL_EditBio(data)
	assert.Error(t, err)
	assert.Nil(t, mock.ExpectationsWereMet())
}

func TestSQL_DeleteBio(t *testing.T) {
	log.SetOutput(io.Discard)
	s, mock := FakeNewAuth(t)
	data := models.ProfileBio{
		NickName: "test",
		Info:     "test info",
	}
	mock.ExpectBegin()
	mock.ExpectPrepare(Sql_deletebio).
		ExpectExec().
		WithArgs(data.NickName).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	err := s.SQL_DeleteBio(data.NickName)
	assert.Nil(t, err)
	assert.Nil(t, mock.ExpectationsWereMet())
}

func TestSQL_DeleteBioError(t *testing.T) {
	log.SetOutput(io.Discard)
	s, mock := FakeNewAuth(t)
	data := models.ProfileBio{
		NickName: "test",
		Info:     "test info",
	}
	mock.ExpectBegin()
	mock.ExpectPrepare(Sql_deletebio).
		ExpectExec().
		WithArgs(data.NickName).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()
	err := s.SQL_DeleteBio(data.NickName)
	assert.Error(t, err)
	assert.Nil(t, mock.ExpectationsWereMet())
}
