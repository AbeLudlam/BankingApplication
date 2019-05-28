CREATE DATABASE users;
GRANT ALL PRIVILEGES ON users.* TO 'appaccount'@'localhost' IDENTIFIED BY 'apppass';
USE users;
CREATE TABLE LoginAccounts (username VARCHAR(255), password VARCHAR(255),  salt VARCHAR(255));
CREATE TABLE BalanceAccount (bName VARCHAR(255), aName VARCHAR(255), amount FLOAT(12) );
INSERT INTO LoginAccounts VALUES ('LudlamAbraham', 'oldpass', '');
INSERT INTO BalanceAccount VALUES ('LudlamAbraham', 'checking', 50.0);
INSERT INTO BalanceAccount VALUES ('LudlamAbraham', 'saving', 40.0);

