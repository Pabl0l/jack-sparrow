CREATE TABLE IF NOT EXISTS guests (guest_id INT(10) UNSIGNED NOT NULL AUTO_INCREMENT, first_name VARCHAR(100) NOT NULL DEFAULT '', last_name VARCHAR(100) NOT NULL DEFAULT '', PRIMARY KEY (guest_id)) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS users (user_id INT(10) UNSIGNED NOT NULL AUTO_INCREMENT, first_name VARCHAR(100) NOT NULL DEFAULT '', last_name VARCHAR(100) NOT NULL DEFAULT '', `user` VARCHAR(15) NOT NULL DEFAULT '', password VARCHAR(32) NOT NULL DEFAULT '', avatar VARCHAR(255) NOT NULL DEFAULT '', last_login TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, failed_login INT(3) NOT NULL DEFAULT 0, PRIMARY KEY (user_id), UNIQUE KEY `user` (`user`)) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS tokens (token VARCHAR(32) NOT NULL, created DATETIME NOT NULL, PRIMARY KEY (token)) ENGINE=InnoDB;

INSERT IGNORE INTO users (`user`, password, first_name, last_name) VALUES ('admin', MD5('password'), 'admin', 'admin'), ('gordonb', MD5('abc123'), 'Gordon', 'Brown'), ('1337', MD5('charley'), 'Hack', 'Me'), ('pablo', MD5('letmein'), 'Pablo', 'Nieto'), ('smithy', MD5('password'), 'Bob', 'Smith');

INSERT IGNORE INTO guests (first_name, last_name) VALUES ('John', 'Doe'), ('Jane', 'Doe');
