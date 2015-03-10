# limesurvey-cas
CAS Authentication plugin for limesurvey (based on phpCAS)
This plugin works with limesurvey 2.0.5

This plugin allows you to force CAS authentication to access the admin interface of Limesurvey.
It also allows you to optionnally create users after the first authentication using LDAP.

## How to install and configure limesurvey-cas

1. Copy the AuthCAS directory into the directory "/plugins" of your limesurvey instance
2. If you want to automatically create users when first connected, you need to define the default permissions in the 'config' array of the file /application/config/config.php

         ```
         'auth_cas_autocreate_permissions' => array(
                 'surveys' => array('create'=>true,'read'=>true,'update'=>true,'delete'=>true,'export'=>true)
         ),
         ```
3. Make sure that one of your admin account has the same id as your CAS account to still be able to manage your installation after the plugin activation
4. Go to "plugins" in the admin interface of LimeSurvey. Configure the plugin. If you choose to auto-create users, you can add a filter to determine who can create his account.
5. When you're done, click on activate. Once done, it won't be possible to authenticate by another mecanism.
