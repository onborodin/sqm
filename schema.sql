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
CREATE TABLE hosts (
    user_id int NOT NULL,
    name text PRIMARY KEY,
    size int
);
COMMIT;
