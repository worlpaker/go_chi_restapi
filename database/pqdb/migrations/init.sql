CREATE TABLE Users (
  Id SERIAL PRIMARY KEY UNIQUE,
  Email varchar(100) NOT NULL UNIQUE,
  Pwd varchar(255) NOT NULL,
  NickName varchar(100) NOT NULL UNIQUE,
  FullName varchar(255),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION trigger_set_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER set_timestamp
BEFORE UPDATE ON Users
FOR EACH ROW
EXECUTE PROCEDURE trigger_set_timestamp();

CREATE TABLE UsersInfo (
  Id SERIAL PRIMARY KEY UNIQUE,
  NickName varchar(100)
);

ALTER TABLE UsersInfo
 ADD FOREIGN KEY (NickName) references Users(NickName);

CREATE TABLE InfoMessage (
  Id SERIAL PRIMARY KEY UNIQUE,
  Message varchar(255),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TRIGGER set_timestamp
BEFORE UPDATE ON InfoMessage
FOR EACH ROW
EXECUTE PROCEDURE trigger_set_timestamp();


ALTER TABLE InfoMessage
 ADD FOREIGN KEY (Id) references UsersInfo(Id);