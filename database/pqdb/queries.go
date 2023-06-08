package pqdb

// Sql Queries

const (
	CreateUser = `INSERT INTO Users (Email, Pwd, NickName, FullName) VALUES ($1, $2, $3, $4);`
	ReadUser   = `SELECT Email, Pwd, NickName, COALESCE(FullName, '') FullName FROM Users WHERE Email = $1;`
	AddBio     = `
	WITH inserted_user AS (
		INSERT INTO UsersInfo (NickName)
		VALUES ($1)
		ON CONFLICT DO NOTHING
		RETURNING Id
	)
	INSERT INTO InfoMessage (Id, Message)
	SELECT Id, $2 FROM inserted_user;
	`
	ReadBio = `
	SELECT Message
	FROM InfoMessage
	INNER JOIN UsersInfo
	ON UsersInfo.Id = InfoMessage.Id
	WHERE UsersInfo.NickName = $1;
	`
	EditBio = `
	UPDATE InfoMessage
	SET message = $2
	FROM (SELECT Id FROM UsersInfo WHERE UsersInfo.NickName = $1) as sub
	WHERE sub.Id = InfoMessage.Id;
	`
	DeleteBio = `
	DELETE FROM InfoMessage
	WHERE Id IN ( 
		SELECT Id FROM UsersInfo
		WHERE UsersInfo.NickName = $1);`
)
