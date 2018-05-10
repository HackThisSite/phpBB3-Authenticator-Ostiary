<?php
/**
*
* @package phpBB Extension - HackThisSite Ostiary Auth
*
*/
if(!defined('IN_PHPBB'))
{
	exit;
}
if(empty($lang) || !is_array($lang))
{
	$lang = array();
}

$lang = array_merge($lang, array(
  'OSTIARY' => 'Ostiary SSO Auth',
	'OSTIARY_REDIS_SERVER' => 'Redis server',
  'OSTIARY_REDIS_SERVER_EXPLAIN' => 'Redis server to use',
  'OSTIARY_CLIENT_ID' => 'Client ID',
  'OSTIARY_CLIENT_ID_EXPLAIN' => 'Which client ID to use on our Ostiary server',
  'OSTIARY_COOKIE_NAME' => 'SSO cookie name',
  'OSTIARY_COOKIE_NAME_EXPLAIN' => 'The cookie name used by the SSO system',
  'OSTIARY_LOGIN_URL' => 'login url',
  'OSTIARY_LOGIN_URL_EXPLAIN' => 'the url to redirect users to for login',
));
