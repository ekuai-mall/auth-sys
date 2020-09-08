SET NAMES utf8;
SET time_zone = '+00:00';
SET foreign_key_checks = 0;
SET sql_mode = 'NO_AUTO_VALUE_ON_ZERO';

SET NAMES utf8mb4;

DROP TABLE IF EXISTS `ekm_auth_user`;
CREATE TABLE `ekm_auth_user`
(
    `id`         int(11) NOT NULL AUTO_INCREMENT,
    `user`       text    NOT NULL,
    `pass`       text    NOT NULL,
    `cookie`     text    NOT NULL,
    `reg_time`   int(11) NOT NULL,
    `login_time` int(11) NOT NULL,
    `ip`         text    NOT NULL,
    `wechat`     text,
    `openid`     text,
	`phone`      text,
	`code`       text,
    `info`       text,
    PRIMARY KEY (`id`)
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4;