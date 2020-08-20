<?php
include './_user_config.php';
try {
	$mysql = new PDO('mysql:dbname=' . DB_NAME . ';host=localhost;', DB_USER, DB_PWD, array
	(PDO::MYSQL_ATTR_INIT_COMMAND => "set names utf8"));
} catch (PDOException $e) {
	echo "数据库连接失败： " . $e->getMessage();
	exit;
}


