BEGIN TRANSACTION;
CREATE TABLE users (
    id int unique NOT NULL PRIMARY KEY,
    name text,
    gecos text,
    password text,
    hash text,
    size int DEFAULT 0,
    quota int DEFAULT 10240
);
CREATE TABLE host (
    user_id text unique NOT NULL PRIMARY KEY,
    host text,
    size int
);
COMMIT;
