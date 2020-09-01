<?php

/**
 * Auth System
 *
 * 一个php鉴权系统插件（类）
 * @author kuai
 * @copyright ekuai 2020
 * @version 2.1
 */

class Auth {
	const ERR_DB = 'database error';
	const ERR_SVR = 'server error';
	const ERR_COOKIE_INVALID = 'cookie invalid';
	protected $mysql;
	public $error = '';
	public $cookieValid = 10 * 60;
	
	public function __construct($dbName, $dbUser, $dbPwd) {
		try {
			$this->mysql = new PDO('mysql:dbname=' . $dbName . ';host=localhost;', $dbUser, $dbPwd, array
			(PDO::MYSQL_ATTR_INIT_COMMAND => "set names utf8"));
			$this->error = '';
		} catch (PDOException $e) {
			$this->error = $e->getMessage();
		}
	}
	
	protected function query($sql, $para, $fetch = PDO::FETCH_ASSOC) {
		if ($this->error !== '') {
			return false;
		} else {
			$a = $this->mysql->prepare($sql);
			if ($a->execute($para)) {
				return $a->fetchAll($fetch);
			} else {
				return false;
			}
		}
	}
	
	protected function getIP() {
		$ip = 'unknown';
		if (getenv("HTTP_CLIENT_IP")) {
			$ip = getenv("HTTP_CLIENT_IP");
		} else if (getenv("HTTP_X_FORWARDED_FOR")) {
			$ip = getenv("HTTP_X_FORWARDED_FOR");
		} else if (getenv("REMOTE_ADDR")) {
			$ip = getenv("REMOTE_ADDR");
		}
		return $ip;
	}
	
	private function randCookie($user) {
		return md5(mt_rand(0, 65536) . $user . mt_rand(0, 65536));
	}
	
	private function ret($status, $ret) {
		return ['status' => $status, 'ret' => $ret];
	}
	
	private function selectUser($user) {
		return $this->query("SELECT `id`,`user`,`cookie`,`login_time` FROM `ekm_auth_user` WHERE `user` = ?", [$user]);
	}
	
	private function selectCookie($userId, $cookie) {
		return $this->query("SELECT * FROM `ekm_auth_user` WHERE `id` = ? AND `cookie` = ?", [$userId, $cookie]);
	}
	
	public function reg($user, $pass) {
		$res = $this->selectUser($user);
		if ($res === false) {
			$ret = $this->ret(110001, self::ERR_DB);
		} else if (!empty($res)) {
			$ret = $this->ret(110002, 'username exists');
		} else {
			$res = $this->query("INSERT INTO `ekm_auth_user` (`user`, `pass`, `cookie`, `reg_time`, `login_time`, `ip`) VALUES (?, ?, '', ?, 0, ?);", [$user, $pass, time(), $this->getIP()]);
			if ($res === false) {
				$ret = $this->ret(110003, self::ERR_DB);
			} else {
				$res = $this->selectUser($user);
				if ($res === false) {
					$ret = $this->ret(110004, self::ERR_DB);
				} else if (empty($res)) {
					$ret = $this->ret(110005, self::ERR_SVR);
				} else {
					$ret = $this->ret(0, $res[0]);
				}
			}
		}
		return $ret;
	}
	
	public function login($user, $pass) {
		$res = $this->query("SELECT * FROM `ekm_auth_user` WHERE `user` = ? AND `pass` = ?", [$user, $pass]);
		if ($res === false) {
			$ret = $this->ret(120001, self::ERR_DB);
		} else if (empty($res)) {
			$ret = $this->ret(120002, 'wrong username or password');
		} else {
			$res = $this->query("UPDATE `ekm_auth_user` SET `cookie` = ?,`login_time` = ?,`ip` = ? WHERE `id` = ?;",
				[$this->randCookie($user), time(), $this->getIP(), $res[0]['id']]);
			if ($res === false) {
				$ret = $this->ret(120003, self::ERR_DB);
			} else {
				$res = $this->selectUser($user);
				if ($res === false) {
					$ret = $this->ret(120004, self::ERR_DB);
				} else if (empty($res)) {
					$ret = $this->ret(120005, self::ERR_SVR);
				} else {
					$ret = $this->ret(0, $res[0]);
				}
			}
		}
		return $ret;
	}
	
	public function logout($userId, $cookie) {
		$res = $this->selectCookie($userId, $cookie);
		if ($res === false) {
			$ret = $this->ret(180001, self::ERR_DB);
		} else if (!empty($res)) {
			$ret = $this->ret(180002, self::ERR_COOKIE_INVALID);
		} else {
			$res = $this->query("UPDATE `ekm_auth_user` SET `cookie` = '',`ip` = ? WHERE `id` = ?;",
				[$this->getIP(), $res[0]['id']]);
			if ($res === false) {
				$ret = $this->ret(180003, self::ERR_DB);
			} else {
				$ret = $this->ret(0, 'success');
			}
		}
		return $ret;
	}
	
	public function heartbeat($userId, $cookie) {
		$res = $this->selectCookie($userId, $cookie);
		if ($res === false) {
			$ret = $this->ret(130001, self::ERR_DB);
		} else if (!empty($res) || $res[0]['login_time'] + $this->cookieValid < time()) {
			$ret = $this->ret(130002, self::ERR_COOKIE_INVALID);
		} else {
			$res = $this->query("UPDATE `ekm_auth_user` SET `login_time` = ?,`ip` = ? WHERE `id` = ?;",
				[time(), $this->getIP(), $res[0]['id']]);
			if ($res === false) {
				$ret = $this->ret(130003, self::ERR_DB);
			} else {
				$res = $this->selectUser($res[0]['user']);
				if ($res === false) {
					$ret = $this->ret(130004, self::ERR_DB);
				} else if (empty($res)) {
					$ret = $this->ret(130005, self::ERR_SVR);
				} else {
					$ret = $this->ret(0, $res[0]);
				}
			}
		}
		return $ret;
	}
	
	public function changePwd($user, $pass, $nPass) {
		$res = $this->query("SELECT * FROM `ekm_auth_user` WHERE `user` = ? AND `pass` = ?", [$user, $pass]);
		if ($res === false) {
			$ret = $this->ret(140001, self::ERR_DB);
		} else if (empty($res)) {
			$ret = $this->ret(140002, 'wrong username or password');
		} else {
			$res = $this->query("UPDATE `ekm_auth_user` SET `pass` = ?,`ip` = ?,`cookie` = '' WHERE `id` = ?;",
				[$nPass, $this->getIP(), $res[0]['id']]);
			if ($res === false) {
				$ret = $this->ret(140003, self::ERR_DB);
			} else {
				$res = $this->selectUser($user);
				if ($res === false) {
					$ret = $this->ret(140004, self::ERR_DB);
				} else if (empty($res)) {
					$ret = $this->ret(140005, self::ERR_SVR);
				} else {
					$ret = $this->ret(0, 'success');
				}
			}
		}
		return $ret;
	}
	
	public function getInfo($userId, $cookie) {
		$res = $this->selectCookie($userId, $cookie);
		if ($res === false) {
			$ret = $this->ret(150001, self::ERR_DB);
		} else if (empty($res)) {
			$ret = $this->ret(150002, self::ERR_COOKIE_INVALID);
		} else {
			$ret = $this->ret(0, $res[0]['info'] ? $res[0]['info'] : '{}');
		}
		return $ret;
	}
	
	public function setInfo($userId, $cookie, $info) {
		$res = $this->selectCookie($userId, $cookie);
		if ($res === false) {
			$ret = $this->ret(160001, self::ERR_DB);
		} else if (empty($res)) {
			$ret = $this->ret(160002, self::ERR_COOKIE_INVALID);
		} else {
			$res = $this->query("UPDATE `ekm_auth_user` SET `info` = ?,`login_time` = ? WHERE `id` = ?;",
				[$info, time(), $userId]);
			if ($res === false) {
				$ret = $this->ret(160003, self::ERR_DB);
			} else {
				$res = $this->selectCookie($userId, $cookie);
				if ($res === false) {
					$ret = $this->ret(160004, self::ERR_DB);
				} else if (empty($res)) {
					$ret = $this->ret(160005, self::ERR_COOKIE_INVALID);
				} else {
					$ret = $this->ret(0, $res[0]['info']);
				}
			}
		}
		return $ret;
	}
	
	public function getWechat($userId, $cookie) {
		$res = $this->selectCookie($userId, $cookie);
		if ($res === false) {
			$ret = $this->ret(150001, self::ERR_DB);
		} else if (empty($res)) {
			$ret = $this->ret(150002, self::ERR_COOKIE_INVALID);
		} else {
			$ret = $this->ret(0, $res['wechat']);
		}
		return $ret;
	}
	
	public function getUserFromSvr($userId, $cookie) {
		$res = $this->selectCookie($userId, $cookie);
		if ($res === false) {
			$ret = $this->ret(150001, self::ERR_DB);
		} else if (empty($res)) {
			$ret = $this->ret(150002, self::ERR_COOKIE_INVALID);
		} else {
			$ret = $this->ret(0, $res);
		}
		return $ret;
	}
	
	public function setWechat($userId, $cookie, $wechat, $openid) {
		$res = $this->selectCookie($userId, $cookie);
		if ($res === false) {
			$ret = $this->ret(160001, self::ERR_DB);
		} else if (empty($res)) {
			$ret = $this->ret(160002, self::ERR_COOKIE_INVALID);
		} else {
			$res = $this->query("UPDATE `ekm_auth_user` SET `wechat` = ?, `openid` = ?, `login_time` = ? WHERE `id` = ?;",
				[$wechat, $openid, time(), $userId]);
			if ($res === false) {
				$ret = $this->ret(160003, self::ERR_DB);
			} else {
				$res = $this->selectCookie($userId, $cookie);
				if ($res === false) {
					$ret = $this->ret(160004, self::ERR_DB);
				} else if (empty($res)) {
					$ret = $this->ret(160005, self::ERR_COOKIE_INVALID);
				} else {
					$ret = $this->ret(0, $res['wechat']);
				}
			}
		}
		return $ret;
	}
}