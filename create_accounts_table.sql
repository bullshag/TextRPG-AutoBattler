-- SQL script to create the accounts table for the AutoBattler login system
-- See project GDD for full authentication flow.
-- This table stores user credentials using salted SHA256 password hashes
-- Compatible with MySQL running on localhost, database autoB

CREATE TABLE IF NOT EXISTS accounts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash CHAR(64) NOT NULL,
    salt CHAR(16) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
