<?php
/**
 * CAS Authentication plugin for limesurvey (based on phpCAS)
 *
 * @author Guillaume Colson <https://github.com/goyome>
 * @author Denis Chenu <https://www.sondages.pro>
 * @copyright 2015-2022 Université de Lorraine
 * @license GPL v2
 * @version 7.0.0
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
class AuthCAS extends AuthPluginBase
{

    protected $storage = 'DbStorage';
    static protected $description = 'CAS authentication plugin';
    static protected $name = 'CAS';
    protected $settings = array(
        'casAuthServer' => array(
            'type' => 'string',
            'label' => 'The servername of the CAS Server without protocol',
            'default' => 'localhost',
        ),
        'casAuthPort' => array(
            'type' => 'int',
            'label' => 'CAS Server listening Port',
            'default' => 8443,
        ),
        'casAuthUri' => array(
            'type' => 'string',
            'label' => 'Relative uri from CAS Server to cas workingdirectory',
            'default' => '/cas',
        ),
        'casVersion' => array(
            'type' => 'select',
            'label' => 'protocol version',
            'options' => array("1.0" => "CAS_VERSION_1_0", "2.0" => "CAS_VERSION_2_0", "3.0" => "CAS_VERSION_3_0", "S1" => "SAML_VERSION_1_1"),
            'default' => "2.0",
        ),
        'serviceBaseUrl' => array(
            'type' => 'string',
            'label' => 'Base URL of this LimeSurvey instance (e.g. https://survey.example.org). Required: prevents CAS ticket theft through a forged Host header',
            'default' => '',
        ),
        'casCACert' => array(
            'type' => 'string',
            'label' => 'Path to the CA certificate (bundle) used to validate the CAS server certificate (e.g. /etc/ssl/certs/ca-certificates.crt). Required',
            'default' => '',
        ),
        'autoGrantCasPermission' => array(
            'type' => 'boolean',
            'label' => 'Automatically grant the "Use CAS authentication" permission to existing (non superadmin) users without explicit setting. Not recommended: a CAS user with the same login as a local account gets access to that account',
            'default' => '0',
        ),
        'casUserIdToLowercase' => array(
            'type' => 'boolean',
            'label' => 'Store the user ID in lowercase in the database to avoid issue with case',
            'default' => '0'
        ),
        'autoCreate' => array(
            'type' => 'select',
            'label' => 'Enable automated creation of user ?',
            'options' => array("0" => "No, don't create user automatically", "1" => "User creation on the first connection", "2" => "User creation from CAS attributes"),
            'default' => '0',
            'submitonchange' => true
        ),
        'casLoginAttr' => array(
            'type' => 'string',
            'label' => 'CAS attribute for login',
            'default' => 'uid'
        ),
        'casFullnameAttr' => array(
            'type' => 'string',
            'label' => 'CAS attribute for fullname',
            'default' => 'displayName'
        ),
        'casMailAttr' => array(
            'type' => 'string',
            'label' => 'CAS attribute for mail',
            'default' => 'mail'
        ),
        'server' => array(
            'type' => 'string',
            'label' => 'Ldap server e.g. ldap://ldap.mydomain.com or ldaps://ldap.mydomain.com'
        ),
        'ldapport' => array(
            'type' => 'string',
            'label' => 'Port number (default when omitted is 389)'
        ),
        'ldapversion' => array(
            'type' => 'select',
            'label' => 'LDAP version',
            'options' => array('2' => 'LDAPv2', '3' => 'LDAPv3'),
            'default' => '3',
            'submitonchange' => true
        ),
        'ldapoptreferrals' => array(
            'type' => 'boolean',
            'label' => 'Select true if referrals must be followed (use false for ActiveDirectory)',
            'default' => '0'
        ),
        'ldaptls' => array(
            'type' => 'boolean',
            'label' => 'Check to enable Start-TLS encryption When using LDAPv3',
            'default' => '1'
        ),
        'searchuserattribute' => array(
            'type' => 'string',
            'label' => 'Attribute to compare to the given login can be uid, cn, mail, ...'
        ),
        'userfullnameattr' => array(
            'type' => 'string',
            'label' => 'Attribute to display the user fullname (displayName, cn, sAMAccountName)',
            'default' => 'displayName'
        ),
        'usersearchbase' => array(
            'type' => 'string',
            'label' => 'Base DN for the user search operation'
        ),
        'extrauserfilter' => array(
            'type' => 'string',
            'label' => 'Optional extra LDAP filter to be ANDed to the basic (searchuserattribute=username) filter. Don\'t forget the outmost enclosing parentheses'
        ),
        'binddn' => array(
            'type' => 'string',
            'label' => 'Optional DN of the LDAP account used to search for the end-user\'s DN. An anonymous bind is performed if empty.'
        ),
        'bindpwd' => array(
            'type' => 'password',
            'label' => 'Password of the LDAP account used to search for the end-user\'s DN if previoulsy set.'
        )
    );

    public function init()
    {
        /**
         * Here you should handle subscribing to the events your plugin will handle
         */
        require_once __DIR__ . '/vendor/autoload.php';
        $this->subscribe('beforeLogin');
        $this->subscribe('newUserSession');
        $this->subscribe('beforeLogout');
        /* check if needed function is available */
        $this->subscribe('beforeActivate');
        /* Global auth option */
        $this->subscribe('getGlobalBasePermissions');
    }

    /**
     * Check if plugin can be activated and used
     */
    public function beforeActivate()
    {
        if (!$this->getEvent()) {
          throw new CHttpException(403);
        }
        if (!function_exists('curl_version')) {
            $this->getEvent()->set('message', $this->gT("You must activate php curl extension"));
            $this->getEvent()->set('success', false);
            return;
        }
    }

    /**
     * Modified getPluginSettings since we have a select box that autosubmits
     * and we only want to show the relevant options.
     * 
     * @param boolean $getValues
     * @return array
     */
    public function getPluginSettings($getValues = true)
    {
        $aPluginSettings = parent::getPluginSettings($getValues);
        if ($getValues) 
        {
            $ldapver = $aPluginSettings['ldapversion']['current'];
            $autoCreate = $aPluginSettings['autoCreate']['current'];

            // If it is a post request, it could be an autosubmit so read posted
            // value over the saved value
            if (App()->request->isPostRequest) 
            {
                $ldapver = App()->request->getPost('ldapversion', $ldapver);
                $aPluginSettings['ldapversion']['current'] = $ldapver;
                $autoCreate = App()->request->getPost('autoCreate', $autoCreate);
                $aPluginSettings['autoCreate']['current'] = $autoCreate;
            }

            if ($autoCreate != 1)
            {
                // Don't create user. Hide unneeded ldap settings
                unset($aPluginSettings['server']);
                unset($aPluginSettings['ldapport']);
                unset($aPluginSettings['ldapversion']);
                unset($aPluginSettings['ldapoptreferrals']);
                unset($aPluginSettings['ldaptls']);
                unset($aPluginSettings['searchuserattribute']);
                unset($aPluginSettings['userfullnameattr']);
                unset($aPluginSettings['usersearchbase']);
                unset($aPluginSettings['extrauserfilter']);
                unset($aPluginSettings['binddn']);
                unset($aPluginSettings['bindpwd']);
            } else {
                if ($ldapver == '2')
                {
                    unset($aPluginSettings['ldaptls']);
                }
            }
            if ($autoCreate != 2)
            {
                unset($aPluginSettings['casFullnameAttr']);
                unset($aPluginSettings['casLoginAttr']);
                unset($aPluginSettings['casMailAttr']);
            }
        }

        return $aPluginSettings;
    }

    public function beforeLogin() 
    {
      if (!is_null($this->api->getRequest()->getParam('noAuthCAS')) || ($this->api->getRequest()->getIsPostRequest())) {
        # Local authentication forced through 'noAuthCAS' url parameter
        $this->getEvent()->set('default', "Authdb");
        return;
      } else {
        // configure phpCAS
        if (!$this->initCasClient()) {
            return;
        }
        //force CAS authentication
        phpCAS::forceAuthentication();

        // Put the user coming from phpCAS in lowercase
        $cas_userid_to_lowercase = $this->get('casUserIdToLowercase');
        if ($cas_userid_to_lowercase)
        {
            $this->setUsername(strtolower(phpCAS::getUser()));
        } else
        {
            $this->setUsername(phpCAS::getUser());
        }
        $oUser = $this->api->getUserByName($this->getUserName());
        $authEvent = $this->getEvent();
        if ($oUser) {
            // Existing user: CAS login is allowed only with the auth_cas permission, even if autoCreate is set
            $allowed = $this->checkLoginCasPermission($oUser->uid);
        } else {
            $allowed = ((int) $this->get('autoCreate') > 0);
        }
        if ($allowed)
        {
            // User authenticated and found. Cas become the authentication system
            $authEvent->set('default', get_class($this));
            $this->setAuthPlugin($authEvent); // This plugin handles authentication, halt further execution of auth plugins
        } elseif ($this->get('is_default', null, null)) 
        {
            // Fall back to another authentication mecanism
            throw new CHttpException(401, 'Wrong credentials for LimeSurvey administration.');
        }
      }
    }

    public function newUserSession() 
    {
        // Do nothing if this user is not AuthCAS type
        $identity = $this->getEvent()->get('identity');
        if ($identity->plugin != 'AuthCAS')  {
            return;
        }
        $authEvent = $this->getEvent();
        $sUser = $this->getUserName();

        $oUser = $this->api->getUserByName($sUser);
        if ($oUser && !$this->checkLoginCasPermission($oUser->uid)) {
            $this->log('CAS login refused for "' . $sUser . '": no auth_cas permission', CLogger::LEVEL_WARNING);
            $this->setAuthFailure(self::ERROR_USERNAME_INVALID);
            return;
        }
        if (is_null($oUser))
        {
            if ((int) $this->get('autoCreate') === 1) 
            {
                // auto-create from LDAP
                // Get configuration settings:
                $ldapserver = $this->get('server');
                $ldapport = $this->get('ldapport');
                $ldapver = $this->get('ldapversion');
                $ldaptls = $this->get('ldaptls');
                $ldapoptreferrals = $this->get('ldapoptreferrals');
                $searchuserattribute = $this->get('searchuserattribute');
                $userfullnameattr = $this->get('userfullnameattr',null,null,'displayname');
                $extrauserfilter = $this->get('extrauserfilter');
                $usersearchbase = $this->get('usersearchbase');
                $binddn = $this->get('binddn');
                $bindpwd = $this->get('bindpwd');
                $casuseridtolowercase = $this->get('casUserIdToLowercase');
                
                // Put the username coming from phpCAS in lowercase             
                if ($casuseridtolowercase)
                {
                    $username = strtolower($sUser);
                } else
                {
                    $username = $sUser;
                }

                if (empty($ldapport)) 
                {
                    $ldapport = 389;
                }

                // Try to connect
                $ldapconn = ldap_connect($ldapserver, (int) $ldapport);
                if (false == $ldapconn) 
                {
                    $this->setAuthFailure(1, gT('Could not connect to LDAP server.'));
                    return;
                }

                // using LDAP version
                if ($ldapver === null) 
                {
                    // If the version hasn't been set, default = 2
                    $ldapver = 2;
                }
                ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, $ldapver);
                ldap_set_option($ldapconn, LDAP_OPT_REFERRALS, $ldapoptreferrals);

                if (!empty($ldaptls) && $ldaptls == '1' && $ldapver == 3 && preg_match("/^ldaps:\/\//", $ldapserver) == 0) 
                {
                    // starting TLS secure layer
                    if (!ldap_start_tls($ldapconn)) 
                    {
                        $this->setAuthFailure(100, ldap_error($ldapconn));
                        ldap_close($ldapconn); // all done? close connection
                        return;
                    }
                }

                // We first do a LDAP search from the username given
                // to find the userDN and then we procced to the bind operation
                if (empty($binddn)) 
                {
                    // There is no account defined to do the LDAP search, 
                    // let's use anonymous bind instead
                    $ldapbindsearch = @ldap_bind($ldapconn);
                } else 
                {
                    // An account is defined to do the LDAP search, let's use it
                    $ldapbindsearch = @ldap_bind($ldapconn, $binddn, $bindpwd);
                }
                if (!$ldapbindsearch) 
                {
                    $this->setAuthFailure(100, ldap_error($ldapconn));
                    ldap_close($ldapconn); // all done? close connection
                    return;
                }
                // Now prepare the search filter (escape the username to prevent LDAP injection)
                $escapedusername = ldap_escape($username, '', LDAP_ESCAPE_FILTER);
                if ($extrauserfilter != "")
                {
                    $usersearchfilter = "(&($searchuserattribute=$escapedusername)$extrauserfilter)";
                } else
                {
                    $usersearchfilter = "($searchuserattribute=$escapedusername)";
                }
                // Search for the user
                $dnsearchres = @ldap_search($ldapconn, $usersearchbase, $usersearchfilter, array($searchuserattribute, $userfullnameattr, "mail"));
                $rescount = $dnsearchres ? ldap_count_entries($ldapconn, $dnsearchres) : 0;
                if ($rescount == 1)
                {
                    $userentry = ldap_get_entries($ldapconn, $dnsearchres);
                    // ldap_get_entries returns lowercase attribute names
                    $fullnamekey = strtolower($userfullnameattr);

                    $oUser = new User;
                    $oUser->users_name = $username;
                    $this->setRandomPassword($oUser);
                    $oUser->full_name = isset($userentry[0][$fullnamekey][0]) ? $userentry[0][$fullnamekey][0] : '';
                    $oUser->parent_id = 1;
                    $oUser->email = isset($userentry[0]["mail"][0]) ? $userentry[0]["mail"][0] : '';


                    if ($oUser->save()) 
                    {
                        if ($this->api->getConfigKey('auth_cas_autocreate_permissions'))
                        {
                           Permission::setPermissions($oUser->uid, 0, 'global', $this->api->getConfigKey('auth_cas_autocreate_permissions'), true);
                        }
                        /* Give connection permission */
                        Permission::model()->setGlobalPermission($oUser->uid, 'auth_cas');
                        if ($this->api->getConfigKey('auth_cas_template_list'))
                        {
                           // Add permission on the templates defined in the config file
                           foreach ($this->api->getConfigKey('auth_cas_template_list') as $template)
                           {
                              $oPermission=new Permission;
                              $oPermission->uid = $oUser->uid;
                              $oPermission->entity_id = 0;
                              $oPermission->entity = 'template';
                              $oPermission->permission = trim($template);
                              $oPermission->read_p = 1;
                              $oPermission->save();
                           }
                        }

                        // read again user from newly created entry
                        $this->setAuthSuccess($oUser, $authEvent);

                        // fire afterAutoCreate event
                        $event = new PluginEvent('afterUserAutoCreate');
                        $event->set('username', $username);
                        App()->getPluginManager()->dispatchEvent($event);

                        return;
                    } else 
                    {
                        ldap_close($ldapconn);
                        $this->log('CAS/LDAP auto-creation: unable to save user "' . $username . '": ' . json_encode($oUser->getErrors()), CLogger::LEVEL_ERROR);
                        $this->setAuthFailure(self::ERROR_USERNAME_INVALID);
                        throw new CHttpException(401, 'Authentication failed.');
                    }
                } else 
                {
                    // if no entry or more than one entry returned
                    // then deny authentication
                    $this->log('CAS/LDAP auto-creation: ' . $rescount . ' LDAP entries found for "' . $username . '" (' . ldap_error($ldapconn) . ')', CLogger::LEVEL_WARNING);
                    $this->setAuthFailure(self::ERROR_USERNAME_INVALID);
                    ldap_close($ldapconn); // all done? close connection
                    throw new CHttpException(401, 'Authentication failed.');
                }
            } elseif ((int) $this->get('autoCreate') === 2)
            {
                $cas_userid_to_lowercase = $this->get('casUserIdToLowercase');
                try {
                    // phpCAS client is already initialized and authenticated in beforeLogin
                    $cas_fullname = phpCAS::getAttribute($this->get('casFullnameAttr'));
                    $cas_mail = phpCAS::getAttribute($this->get('casMailAttr'));
                } catch (Exception $e)
                {
                    $this->log('CAS auto-creation: attributes not found for "' . $sUser . '": ' . $e->getMessage(), CLogger::LEVEL_ERROR);
                    $this->setAuthFailure(self::ERROR_USERNAME_INVALID);
                    throw new CHttpException(401, 'Authentication failed.');
                }
                $oUser = new User;
                $oUser->users_name = phpCAS::getUser();
                if ($cas_userid_to_lowercase) {
                    $oUser->users_name = strtolower($oUser->users_name);
                }
                $this->setRandomPassword($oUser);
                $oUser->full_name = is_array($cas_fullname) ? reset($cas_fullname) : (string) $cas_fullname;
                $oUser->parent_id = 1;
                $oUser->email = is_array($cas_mail) ? reset($cas_mail) : (string) $cas_mail;
                if ($oUser->save())
                {
                    if ($this->api->getConfigKey('auth_cas_autocreate_permissions'))
                    {
                        Permission::setPermissions($oUser->uid, 0, 'global', $this->api->getConfigKey('auth_cas_autocreate_permissions'), true);
                    }
                    Permission::model()->setGlobalPermission($oUser->uid, 'auth_cas');
                    $this->setAuthSuccess($oUser, $authEvent);

                    // fire afterAutoCreate event
                    $event = new PluginEvent('afterUserAutoCreate');
                    $event->set('username', $oUser->users_name);
                    App()->getPluginManager()->dispatchEvent($event);

                    return;
                } else
                {
                    $this->log('CAS auto-creation: unable to save user "' . $sUser . '": ' . json_encode($oUser->getErrors()), CLogger::LEVEL_ERROR);
                    $this->setAuthFailure(self::ERROR_USERNAME_INVALID);
                    throw new CHttpException(401, 'Authentication failed.');
                }
            }
        } else 
        {
            $this->setAuthSuccess($oUser, $authEvent);
            return;
        }
    }

    public function beforeLogout() 
    {
        // configure phpCAS
        if (!$this->initCasClient()) {
            return;
        }
        // logout from CAS
        phpCAS::logout();
    }

    /**
     * Initialize the phpCAS client with a fixed service URL and a validated CAS server certificate
     * @return boolean true if the client is ready to be used
     */
    private function initCasClient()
    {
        if (phpCAS::isInitialized()) {
            return true;
        }
        $cas_host = $this->get('casAuthServer');
        $service_base_url = trim((string) $this->get('serviceBaseUrl'));
        $ca_cert = trim((string) $this->get('casCACert'));
        if (empty($cas_host)) {
            return false;
        }
        if (!preg_match('#^https?://[^/?\#]+#i', $service_base_url)) {
            $this->log('CAS authentication disabled: "serviceBaseUrl" setting is missing or invalid', CLogger::LEVEL_ERROR);
            return false;
        }
        if (empty($ca_cert) || !is_readable($ca_cert)) {
            $this->log('CAS authentication disabled: "casCACert" setting is missing or the file is not readable', CLogger::LEVEL_ERROR);
            return false;
        }
        // Initialize phpCAS (service_base_url avoids building the service URL from the Host header : CVE-2022-39369)
        phpCAS::client(
            $this->get('casVersion'),
            $cas_host,
            (int) $this->get('casAuthPort'),
            $this->get('casAuthUri'),
            $service_base_url,
            false
        );
        // validate the SSL certificate of the CAS server
        phpCAS::setCasServerCACert($ca_cert, true);
        return true;
    }

    /**
     * Set a random password on a newly created user (never communicated: authentication is done by CAS)
     * @param User $oUser
     * @return void
     */
    private function setRandomPassword($oUser)
    {
        $sPassword = function_exists('random_bytes') ? bin2hex(random_bytes(32)) : createPassword();
        if (method_exists($oUser, 'setPassword')) {
            $oUser->setPassword($sPassword);
        } else {
            $oUser->password = hash('sha256', $sPassword);
        }
    }

    /**
     * Add AuthCas Permission to global Permission
     * @return void
     */
    public function getGlobalBasePermissions()
    {
        $this->getEvent()->append('globalBasePermissions', array(
            'auth_cas' => array(
                'create' => false,
                'update' => false,
                'delete' => false,
                'import' => false,
                'export' => false,
                'title' => $this->gT("Use CAS authentication"),
                'description' => $this->gT("Use CAS authentication"),
                'img' => 'fa fa-user-circle-o'
            ),
        ));
    }

    /**
     * @inheritoc
     * Replace to use own event
     * @return AuthPluginBase
     */
    public function setAuthPlugin(LimeSurvey\PluginManager\PluginEvent $event = null)
    {
        if (empty($event)) {
            $event = $this->getEvent();
        }
        $identity = $event->get('identity');
        $identity->plugin = get_class($this);
        $event->stop();

        return $this;
    }

    /**
     * @inheritoc
     * Replace to use own event
     * @see https://bugs.limesurvey.org/view.php?id=17654
     *
     * @param User $user
     * @param PluginEvent $event
     * @return AuthPluginBase
     */
    public function setAuthSuccess(User $user, LimeSurvey\PluginManager\PluginEvent $event = null)
    {
        if (empty($event)) {
            $event = $this->getEvent();
        }
        $identity = $event->get('identity');
        $identity->id = $user->uid;
        $identity->user = $user;
        $event->set('identity', $identity);
        $event->set('result', new LSAuthResult(self::ERROR_NONE));

        return $this;
    }

    /**
     * Check if have Log in permission
     * Line is set : read it
     * Line is not set : refused, unless autoGrantCasPermission is enabled and the user is not a superadmin
     * The superadmin implicit rights are not used : a superadmin needs an explicit auth_cas permission.
     * @var integer userid
     * @return boolean
     */
    private function checkLoginCasPermission($userid)
    {
        $oPermission = Permission::model()->find(
            "entity = 'global' AND entity_id = 0 AND uid = :uid AND permission = 'auth_cas'",
            array( ':uid' => $userid)
        );
        if (!empty($oPermission)) {
            return (bool) $oPermission->read_p;
        }
        if (!$this->get('autoGrantCasPermission')) {
            return false;
        }
        if (Permission::model()->hasGlobalPermission('superadmin', 'read', $userid)) {
            return false;
        }
        /* Set it for next login */
        Permission::model()->setGlobalPermission($userid, 'auth_cas');
        return true;
    }
}
