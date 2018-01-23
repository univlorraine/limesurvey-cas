# limesurvey-cas
CAS Authentication plugin for limesurvey (based on phpCAS)
This version of the plugin works with limesurvey 2.0.5 and above but below 3.x

This plugin allows you to force CAS authentication to access the admin interface of Limesurvey.
It also allows you to optionnally create users after the first authentication using LDAP or CAS attributes.
If this plugin is activated, you can force local authentication (e.g. to connect as admin) by using the url : ls_url/index.php/admin/authentication/sa/login?noAuthCAS=true

## Warning : update from a version prior to 0.1.0

Since 0.1.0, you have to define the version of your CAS server in the plugin config. You need to deactivate the CAS plugin before the upgrade to avoid breaking authentication.
After upgrading AuthCAS.php, modify your plugin parameters and then activate CAS plugin again.

## How to install and configure limesurvey-cas

1. Copy the AuthCAS directory into the directory "/plugins" of your limesurvey instance
2. If you want to automatically create users when first connected, you need to define the default permissions in the 'config' array of the file /application/config/config.php

         ```
         'auth_cas_autocreate_permissions' => array(
                 'surveys' => array('create'=>true)
         ),
         'auth_cas_template_list' => array(
                 'default',
                 'limespired'
         ),
         ```
3. Go to "plugins" in the admin interface of LimeSurvey. Configure the plugin. If you choose to auto-create users, you can add a filter to determine who has the right to connect without a previously created account.
4. When you're done, click on activate. Once done, it won't be possible to authenticate by another mechanism unless you use the specific url ls_url/index.php/admin/authentication/sa/login?noAuthCAS=true.

## How to avoid sending password when creating new user

When a user is automatically created, there's no mail sent to him.

But if you're creating a user in the admin interface, a mail is sent containing the generated password. If you want to avoid confusion and not send the password in the email, you can add the following configuration in the file /application/config/config.php

         ```
         'auth_webserver' => true
         ```
This change indicates to Limesurvey that the authentication is managed by an external system.
