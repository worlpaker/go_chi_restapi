package pqdb

// Sql Queries

const (
	Sql_createuser = `INSERT INTO Users (Email, Pwd, NickName, FullName) VALUES ($1, $2, $3, $4);`
	Sql_readuser   = `SELECT Email, Pwd, NickName, COALESCE(FullName, '') FullName FROM Users WHERE Email = $1;`
	Sql_addbio     = `
	WITH inserted_user AS (
		INSERT INTO UsersInfo (NickName)
		VALUES ($1)
		ON CONFLICT DO NOTHING
		RETURNING Id
	)
	INSERT INTO InfoMessage (Id, Message)
	SELECT Id, $2 FROM inserted_user;
	`
	Sql_readbio = `
	SELECT Message
	FROM InfoMessage
	INNER JOIN UsersInfo
	ON UsersInfo.Id = InfoMessage.Id
	WHERE UsersInfo.NickName = $1;
	`
	Sql_editbio = `
	UPDATE InfoMessage
	SET message = $2
	FROM (SELECT Id FROM UsersInfo WHERE UsersInfo.NickName = $1) as sub
	WHERE sub.Id = InfoMessage.Id;
	`
	Sql_deletebio = `
	DELETE FROM InfoMessage
	WHERE Id IN ( 
		SELECT Id FROM UsersInfo
		WHERE UsersInfo.NickName = $1);`
)
