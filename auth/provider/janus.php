<?php
/**
* TODO: license
*
*/

namespace hackthissite\ostiary\auth\provider;

require_once(__DIR__ . '/../../vendor/autoload.php');

/**
 * Database authentication provider for phpBB3
 * This is for authentication via the integrated user table
 */
class janus extends \phpbb\auth\provider\base
{
  /** @var \phpbb\db\driver\driver_interface $db */
  protected $db;

  /**
  * {@inheritdoc}
  */
  public function init()
  {
    try {
      $test = new \Ostiary\Client(array(
        'driver' => 'redis',
        'redis' => $this->config['ostiary_redis_server'],
        'id' => $this->config['ostiary_client_id'],
      ));
    } catch (Exception $ex) {
      return $ex->getMessage();
    }
    return false;
  }
	/**
	 * Database Authentication Constructor
	 *
	 * @param	\phpbb\db\driver\driver_interface		$db
	 * @param	\phpbb\config\config 		$config
	 * @param	\phpbb\request\request		$request
	 * @param	\phpbb\user			$user
	 * @param	string				$phpbb_root_path
	 * @param	string				$php_ext
	 */
	public function __construct(\phpbb\db\driver\driver_interface $db, \phpbb\config\config $config, \phpbb\request\request $request, \phpbb\user $user, $phpbb_root_path, $php_ext)
	{
		$this->db = $db;
		$this->config = $config;
		$this->request = $request;
		$this->user = $user;
		$this->phpbb_root_path = $phpbb_root_path;
		$this->php_ext = $php_ext;
	}
  
  /**
   * {@inheritdoc}
   */
   
  public function acp()
  {
    // These are fields required in the config table
    return array(
      'ostiary_redis_server', 'ostiary_client_id', 'ostiary_cookie_name',
    );
  }
  
  /**
	 * {@inheritdoc}
	 */
   
	public function get_acp_template($new_config)
	{
    $this->user->add_lang_ext('hackthissite/ostiary', 'acp/board');
		return array(
			'TEMPLATE_FILE'	=> '@hackthissite_ostiary/auth_provider_ostiary.html',
			'TEMPLATE_VARS'	=> array(
				'AUTH_OSTIARY_CLIENT_ID'		=> $new_config['ostiary_client_id'],
				'AUTH_OSTIARY_REDIS_SERVER'		=> $new_config['ostiary_redis_server'],
        'AUTH_OSTIARY_COOKIE_NAME'		=> $new_config['ostiary_cookie_name'],
			),
		);
	}

	/**
	 * {@inheritdoc}
	 */
	public function login($username, $password)
	{
    // Auth plugins get the password untrimmed.
		// For compatibility we trim() here.
		$password = trim($password);
    
		// do not allow empty password
		if (!$password)
		{
			return array(
				'status'	=> LOGIN_ERROR_PASSWORD,
				'error_msg'	=> 'NO_PASSWORD_SUPPLIED',
				'user_row'	=> array('user_id' => ANONYMOUS),
			);
		}
		if (!$username)
		{
			return array(
				'status'	=> LOGIN_ERROR_USERNAME,
				'error_msg'	=> 'LOGIN_ERROR_USERNAME',
				'user_row'	=> array('user_id' => ANONYMOUS),
			);
		}
		$username_clean = utf8_clean_string($username);
		$sql = 'SELECT *
			FROM ' . USERS_TABLE . "
			WHERE username_clean = '" . $this->db->sql_escape($username_clean) . "'";
		$result = $this->db->sql_query($sql);
		$row = $this->db->sql_fetchrow($result);
		$this->db->sql_freeresult($result);
		if (($this->user->ip && !$this->config['ip_login_limit_use_forwarded']) ||
			($this->user->forwarded_for && $this->config['ip_login_limit_use_forwarded']))
		{
			$sql = 'SELECT COUNT(*) AS attempts
				FROM ' . LOGIN_ATTEMPT_TABLE . '
				WHERE attempt_time > ' . (time() - (int) $this->config['ip_login_limit_time']);
			if ($this->config['ip_login_limit_use_forwarded'])
			{
				$sql .= " AND attempt_forwarded_for = '" . $this->db->sql_escape($this->user->forwarded_for) . "'";
			}
			else
			{
				$sql .= " AND attempt_ip = '" . $this->db->sql_escape($this->user->ip) . "' ";
			}
			$result = $this->db->sql_query($sql);
			$attempts = (int) $this->db->sql_fetchfield('attempts');
			$this->db->sql_freeresult($result);
			$attempt_data = array(
				'attempt_ip'			=> $this->user->ip,
				'attempt_browser'		=> trim(substr($this->user->browser, 0, 149)),
				'attempt_forwarded_for'	=> $this->user->forwarded_for,
				'attempt_time'			=> time(),
				'user_id'				=> ($row) ? (int) $row['user_id'] : 0,
				'username'				=> $username,
				'username_clean'		=> $username_clean,
			);
			$sql = 'INSERT INTO ' . LOGIN_ATTEMPT_TABLE . $this->db->sql_build_array('INSERT', $attempt_data);
			$this->db->sql_query($sql);
		}
		else
		{
			$attempts = 0;
		}
		if (!$row)
		{
			if ($this->config['ip_login_limit_max'] && $attempts >= $this->config['ip_login_limit_max'])
			{
				return array(
					'status'		=> LOGIN_ERROR_ATTEMPTS,
					'error_msg'		=> 'LOGIN_ERROR_ATTEMPTS',
					'user_row'		=> array('user_id' => ANONYMOUS),
				);
			}
			return array(
				'status'	=> LOGIN_ERROR_USERNAME,
				'error_msg'	=> 'LOGIN_ERROR_USERNAME',
				'user_row'	=> array('user_id' => ANONYMOUS),
			);
		}
		$show_captcha = ($this->config['max_login_attempts'] && $row['user_login_attempts'] >= $this->config['max_login_attempts']) ||
			($this->config['ip_login_limit_max'] && $attempts >= $this->config['ip_login_limit_max']);
		// If there are too many login attempts, we need to check for a confirm image
		// Every auth module is able to define what to do by itself...
		if ($show_captcha)
		{
			/* @var $captcha_factory \phpbb\captcha\factory */
			$captcha_factory = $this->phpbb_container->get('captcha.factory');
			$captcha = $captcha_factory->get_instance($this->config['captcha_plugin']);
			$captcha->init(CONFIRM_LOGIN);
			$vc_response = $captcha->validate($row);
			if ($vc_response)
			{
				return array(
					'status'		=> LOGIN_ERROR_ATTEMPTS,
					'error_msg'		=> 'LOGIN_ERROR_ATTEMPTS',
					'user_row'		=> $row,
				);
			}
			else
			{
				$captcha->reset();
			}
		}
		// Check password ...
		if (true)
		{
			
			$sql = 'DELETE FROM ' . LOGIN_ATTEMPT_TABLE . '
				WHERE user_id = ' . $row['user_id'];
			$this->db->sql_query($sql);
			if ($row['user_login_attempts'] != 0)
			{
				// Successful, reset login attempts (the user passed all stages)
				$sql = 'UPDATE ' . USERS_TABLE . '
					SET user_login_attempts = 0
					WHERE user_id = ' . $row['user_id'];
				$this->db->sql_query($sql);
			}
			// User inactive...
			if ($row['user_type'] == USER_INACTIVE || $row['user_type'] == USER_IGNORE)
			{
				return array(
					'status'		=> LOGIN_ERROR_ACTIVE,
					'error_msg'		=> 'ACTIVE_ERROR',
					'user_row'		=> $row,
				);
			}
			// Successful login... set user_login_attempts to zero...
			return array(
				'status'		=> LOGIN_SUCCESS,
				'error_msg'		=> false,
				'user_row'		=> $row,
			);
		}
		// Password incorrect - increase login attempts
		$sql = 'UPDATE ' . USERS_TABLE . '
			SET user_login_attempts = user_login_attempts + 1
			WHERE user_id = ' . (int) $row['user_id'] . '
				AND user_login_attempts < ' . LOGIN_ATTEMPTS_MAX;
		$this->db->sql_query($sql);
		// Give status about wrong password...
		return array(
			'status'		=> ($show_captcha) ? LOGIN_ERROR_ATTEMPTS : LOGIN_ERROR_PASSWORD,
			'error_msg'		=> 'LOGIN_ERROR_PASSWORD',
			'user_row'		=> $row,
		);
	}

  
  /**
    * {@inheritdoc}
    */
  public function autologin() {
    // gotta use fancy phpbb methods to aquire cookies, otherwise it'll fuck shit up
    $ssoid = $this->request->variable($this->config['ostiary_cookie_name'], '', true,\phpbb\request\request_interface::COOKIE);
    
    if (empty($ssoid)) {
      // fail! no auto login possible
      return array();
    }
    
    
    // TODO: fetch proper username and other details from remote server
    try {
      $ostiary = new \Ostiary\Client(array(
        'driver' => 'redis',
        'redis' => $this->config['ostiary_redis_server'],
        'id' => $this->config['ostiary_client_id'],
      ));
      $session = $ostiary->getSession($ssoid);
      if ($session == NULL) {
        return array();
      }
      
      $bucket_global = $session->getBucket('global');
      //$bucket_global['email'] = 'bar@foo.com';
      $username = $bucket_global['username'];
      
      
      $username_clean = utf8_clean_string($username);
      $sql = 'SELECT *
          FROM ' . USERS_TABLE . "
          WHERE username_clean = '" . $this->db->sql_escape($username_clean) . "'";
      $result = $this->db->sql_query($sql);
      $row = $this->db->sql_fetchrow($result);
      $this->db->sql_freeresult($result);
      
      
      // TODO: optionally add checks to see if user has a bunch of failed login attempts? then again thats the remote servers problem
      
      if ($row) {
        if ($row['user_type'] == USER_INACTIVE || $row['user_type'] == USER_IGNORE)
  			{
          
  				return array(); //ignored or inactive users can't login
  			} else {
          
          //$this->user->session_create($row['user_id'], false, true, true);
          $this->user->set_login_key($row['user_id'], false, false);
          return $row;
        }
      } else {
        // user was not found in local DB, it must be new
        // retrieve default group id
  			$sql = 'SELECT group_id
  				FROM ' . GROUPS_TABLE . "
  				WHERE group_name = '" . $this->db->sql_escape('REGISTERED') . "'
  					AND group_type = " . GROUP_SPECIAL;
  			$result = $this->db->sql_query($sql);
  			$row = $this->db->sql_fetchrow($result);
  			$this->db->sql_freeresult($result);
  			if (!$row)
  			{
  				trigger_error('NO_GROUP');
  			}
        
        $user_row = array(
  				'username'		=> $username,
  				'user_password'	=> '',
  				'user_email'	=> 'poop@poop.com',
  				'group_id'		=> (int) $row['group_id'],
  				'user_type'		=> USER_NORMAL,
  				'user_ip'		=> $this->user->ip,
  				'user_new'		=> ($this->config['new_member_post_limit']) ? 1 : 0,
  			);
        
        if (!function_exists('user_add'))
  			{
  				include($this->phpbb_root_path . 'includes/functions_user.' . $this->php_ext);
  			}
  			// create the user if he does not exist yet
  			user_add($user_row);
        
        $sql = 'SELECT *
  				FROM ' . USERS_TABLE . "
  				WHERE username_clean = '" . $this->db->sql_escape(utf8_clean_string($php_auth_user)) . "'";
  			$result = $this->db->sql_query($sql);
  			$row = $this->db->sql_fetchrow($result);
  			$this->db->sql_freeresult($result);
  			if ($row)
  			{
          //$this->user->session_create($row['user_id'], false, true, true);
          $this->user->set_login_key($row['user_id'], false, false);
  				return $row;
  			}
      }
    } catch (Exception $ex) {
      return array();
    }
    
    
    return array();
  }
  
  /**
    * {@inheritdoc}
    */
  public function validate_session($user)
  {
    //return true;
    $ssoid = $this->request->variable($this->config['ostiary_cookie_name'], '', true,\phpbb\request\request_interface::COOKIE);
    
    if (empty($ssoid)) {
      // fail! no auto login possible
      return array();
    }
    
    try {
      $ostiary = new \Ostiary\Client(array(
        'driver' => 'redis',
        'redis' => $this->config['ostiary_redis_server'],
        'id' => $this->config['ostiary_client_id'],
      ));
      $session = $ostiary->getSession($ssoid);
      if ($session != NULL) {
        $bucket_global = $session->getBucket('global');
        $username = $bucket_global['username'];
        if ($username === $user['username'])
        {
          return true;
        } // else, invalidate the SSO? or not cuz they may be browsing without wanting to be logged in on forums  
      }
    } catch (Exception $ex) {
      //return array();
    }
    
    //not logged in on SSO AND forum, could still be legit session if its an anon user or bot
    
    
    // user is not set. A valid session is now determined by the user type (anonymous/bot or not)
    if ($user['user_type'] == USER_IGNORE)
    {
      
      return true;
    }
    
    $this->user->reset_login_keys(false);
    return false;
  }
}
