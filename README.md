# limesurvey-cas
CAS Authentication plugin for limesurvey (based on phpCAS)
This version of the plugin works with limesurvey 2.6 and above (except 2.6.3)
Check the release v2.0 to get the version for Limesurvey 2.x

This plugin allows you to force CAS authentication to access the admin interface of Limesurvey.
It also allows you to optionnally create users after the first authentication using LDAP or CAS attributes.
If this plugin is activated, you can force local authentication (e.g. to connect as admin) by using the url : ls_url/index.php/admin/authentication/sa/login?noAuthCAS=true

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
3. Go to "plugins" in the admin interface of LimeSurvey. Configure the plugin. The following settings are **required**, CAS authentication stays disabled (and an error is logged) until they are set:
   - `serviceBaseUrl`: the public base URL of your LimeSurvey instance, e.g. `https://survey.example.org`. It is used to build the CAS service URL instead of the HTTP `Host` header (CVE-2022-39369).
   - `casCACert`: path to the CA certificate (bundle) used to validate the certificate of the CAS server, e.g. `/etc/ssl/certs/ca-certificates.crt` (Debian/Ubuntu) or `/etc/pki/tls/certs/ca-bundle.crt` (RHEL).

   If you choose to auto-create users, you can add a filter to determine who has the right to connect without a previously created account.
4. When you're done, click on activate. Once done, it won't be possible to authenticate by another mechanism unless you use the specific url ls_url/index.php/admin/authentication/sa/login?noAuthCAS=true.

## How to avoid sending password when creating new user

When a user is automatically created, there's no mail sent to him.

But if you're creating a user in the admin interface, a mail is sent containing the generated password. If you want to avoid confusion and not send the password in the email, you can add the following configuration in the file /application/config/config.php

         ```
         'auth_webserver' => true
         ```
This change indicates to Limesurvey that the authentication is managed by an external system.

## How to store lowercase user IDs in the database

When a user connects for the first time, the identifier retrieved by the CAS plugin is stored in the database as the user typed it.

Example: User logged with `JohnDoe`, userId stored in the database will be` JohnDoe`

You can force the identifier to be lowered in the database with the `casUserIdToLowercase` option.

Be careful, if you activate this option, it will probably be necessary to update user identifiers already registered in the database.

Execute this SQL statement :
```
UPDATE lime_users SET users_name = LOWER(users_name);
```

## Who can log in with CAS

An existing LimeSurvey user can log in with CAS only if they have the global permission "Use CAS authentication" (`auth_cas`) set explicitly, even when automatic user creation is enabled. Superadministrators always need this explicit permission.

Before version 7.0.0, the permission was granted automatically to every existing user on their first CAS login. This let a CAS account take over the local account with the same login (for example `admin`). If you need the old behaviour for regular users, enable the `autoGrantCasPermission` setting: it never applies to superadministrators.

Users created automatically by the plugin receive the permission when they are created.

## Security recommendations

- Use LDAPv3 with StartTLS or `ldaps://` for the LDAP auto-creation mode, so that the bind password is not sent in clear text.
- The local login form stays available with `?noAuthCAS=true`. Restrict access to it (IP filtering on the web server, brute force protection) if you do not need it.

## Troubleshooting

If LimeSurvey displays its local login form instead of redirecting to CAS, run the diagnostic script from the command line, with the web server user:

```
sudo -u www-data php tools/check-authcas.php /path/to/limesurvey [cas_login]
```

It checks the plugin files, the plugin settings (`serviceBaseUrl`, `casCACert`...), the TLS connection to the CAS server and, if `cas_login` is given, whether this user is allowed to log in with CAS. It only reads the database. Do not copy this script into a directory served by the web server.
