<?php


namespace hackthissite\ostiary\event;

/**
* @ignore
*/
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
* Event listener
*/
class listener implements EventSubscriberInterface
{
  
  /** @var \phpbb\user */
  protected $user;
  
	/** @var \hackthissite\ostiary\auth\provider\janus */
  protected $ostiary;
  
  /** @var \phpbb\request\request	*/
  protected $request;
  
  /** @var string	*/
  protected $phpbb_root_path;

  /**
  * @param	\phpbb\user			$user
  * @param	\hackthissite\ostiary\auth\provider\janus 			$ostiary
  * @param	\phpbb\request\request		$request
  * @param	string				$phpbb_root_path
  */
	public function __construct(\phpbb\user $user, \hackthissite\ostiary\auth\provider\janus $ostiary, \phpbb\request\request $request, $phpbb_root_path)
	{
    $this->user = $user;
    $this->ostiary = $ostiary;
    $this->request = $request;
    $this->phpbb_root_path = $phpbb_root_path;
	}

	static public function getSubscribedEvents()
	{
		return array(
			'core.login_box_before'	=> 'login_box_before',
		);
	}

  /**
  * Make sure autologin is set as soon as user gets to the login form.
  * 
  */
	public function login_box_before($event)
	{
    // running the autologin function to see if we should login the user
    
    $uri = explode('/', $this->request->server('REQUEST_URI'));
    
    if (!$event['admin'])
    { // its not the admin page

      $row = $this->ostiary->autologin();
      
      if (sizeof($row) && !empty($row['user_id']) && is_numeric($row['user_id']) && $row['user_id'] != 0)
      { //the user was totally legit and what not
        $this->user->session_create($row['user_id'], false, true, true);
        redirect($phpbb_root_path); 
      } else {
        redirect($this->ostiary->config['ostiary_login_url'], false, true);
      }
    }
	}
  
}
