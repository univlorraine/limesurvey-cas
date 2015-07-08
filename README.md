# limesurvey-cas
CAS Authentication plugin for limesurvey (based on phpCAS)
This plugin works with limesurvey 2.0.5 and higher

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
         ```
3. Make sure that one of your admin account has the same id as your CAS account to still be able to manage your installation after the plugin activation
4. Go to "plugins" in the admin interface of LimeSurvey. Configure the plugin. If you choose to auto-create users, you can add a filter to determine who has the right to connect without a previously created account.
5. When you're done, click on activate. Once done, it won't be possible to authenticate by another mechanism.
