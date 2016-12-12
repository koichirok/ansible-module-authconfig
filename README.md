# Andible authconfig module
[![Travis](https://travis-ci.org/koichirok/ansible-module-authconfig.svg?branch=master)](https://travis-ci.org/koichirok/ansible-module-authconfig)

Manages system authentication resources with _authconfig_

## Requirements
* authconfig package

## Install

TBD.

## Synopsis
 Configurering system authentication resources with _authconfig(8)_

## Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| enablereqlower  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Require at least one lowercase character/Do not require lowercase characters in a password  |
| enablecachecreds  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable caching of user credentials in SSSD by default  |
| smbservers  |   no  |  | |  Specify names of servers to authenticate against  |
| enablerequiresmartcard  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Require/Do not require smart card for authentication by default  |
| passalgo  |   no  |  | <ul> <li>descrypt</li>  <li>bigcrypt</li>  <li>md5</li>  <li>sha256</li>  <li>sha512</li> </ul> |  Specify hash/crypt algorithm for new passwords  |
| smbsecurity  |   no  |  | <ul> <li>user</li>  <li>server</li>  <li>domain</li>  <li>ads</li> </ul> |  Specify security mode to use for samba and winbind  |
| enablereqdigit  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Require at least one digit/Do not require digits in a password  |
| enableipav2  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable IPAv2 for user information and authentication by default  |
| enablewinbindusedefaultdomain  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Configures winbind to assume that users with no domain in their user names are domain/not domain users  |
| ldapserver  |   no  |  | |  default LDAP server hostname or URI  |
| enablepreferdns  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Prefer/Do not prefer dns over wins or nis for hostname resolution  |
| krb5kdc  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Specify default kerberos KDC  |
| ldapbasedn  |   no  |  | |  default LDAP base DN  |
| enableforcelegacy  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  When set to _no_, use SSSD implicitly if it supports the configuration. Set to _yes_  |
| smbrealm  |   no  |  | |  Specify default realm for samba and winbind when security=ads  |
| enablesssd  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Set to _yes_ to enable SSSD for user information by default with manually managed configuration. Set to _no_ disable SSSD for user information by default (still used for supported configurations)  |
| enablekrb5realmdns  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable use of DNS to find kerberos realms  |
| smbworkgroup  |   no  |  | |  Specify workgroup authentication servers are in  |
| ipav2domain  |   no  |  | |  Specify the IPAv2 domain the system should be part of  |
| enableshadow  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable shadowed passwords by default  |
| enablefingerprint  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable authentication with fingerprint readers by default  |
| enablekrb5kdcdns  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable use of DNS to find kerberos KDCs  |
| passmaxrepeat  |   no  |  | |  Specify maximum number of same consecutive characters in a password  |
| krb5realm  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Specify default kerberos realm  |
| winbindjoin  |   no  |  | |  Specify administrator account to Join the winbind domain or ads realm now  |
| enablelocauthorize  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  When set to _yes_, local authorization is sufficient for local users. Set to _no_  |
| ipav2server  |   no  |  | |  Specify the server for the IPAv2 domain  |
| enablewinbindoffline  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Configures winbind to allow/prevent offline login  |
| smartcardmodule  |   no  |  | |  Specify default smart card module to use  |
| enablesysnetauth  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Set to _yes_ to authenticate system accounts by network services. Set to _no_  |
| enablewins  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable wins for hostname resolution  |
| nostart  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  do not start/stop portmap, ypbind, and nscd  |
| ldaploadcacert  |   no  |  | |  load CA certificate from the URL  |
| enablerfc2307bis  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable use of RFC-2307bis schema for LDAP user information lookups  |
| enablewinbindkrb5  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Winbind will use Kerberos 5 to authenticate/the default authentication method  |
| enablesssdauth  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Set to _yes_ to enable SSSD for authentication by default with manually managed configuration. Set to _no_ to disable SSSD for authentication by default (still used for supported configurations)  |
| enablesmartcard  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable authentication with smart card by default  |
| passminlen  |   no  |  | |  Specify minimum length of a password  |
| enablecache  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable caching of user information by defaul  |
| enablewinbindauth  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable winbind for authentication by default  |
| hesiodrhs  |   no  |  | |  Specify default hesiod RHS  |
| hesiodlhs  |   no  |  | |  Specify default hesiod LHS  |
| enablehesiod  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable hesiod for user information by default  |
| enablerequpper  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Require at least one uppercase character/Do not require uppercase characters in a password  |
| enablepamaccess  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Check/Do not check access.conf during account authorization  |
| winbindtemplateshell  |   no  |  | |  Specify the shell which winbind-created users will have as their login shell  |
| enablekrb5  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable kerberos authentication by default  |
| enablewinbind  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable winbind for user information by default  |
| ipav2join  |   no  |  | |  Specify the account to join the IPAv2 domain  |
| krb5adminserver  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Specify default kerberos admin server  |
| ipav2realm  |   no  |  | |  Specify the realm for the IPAv2 domain  |
| enablenis  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable NIS for user information by default  |
| enableldapauth  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable LDAP for authentication by default  |
| enableldap  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable LDAP for user information by default  |
| enablereqother  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Require at least one other character/Do not require other characters in a password  |
| winbindtemplatehomedir  |   no  |  | |  Specify the directory which winbind-created users will have as home directories  |
| enablemkhomedir  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Create/Don't create home directories for users on their first login  |
| nisdomain  |   no  |  | |  Specify default NIS domain  |
| passmaxclassrepeat  |   no  |  | |  Specify maximum number of consecutive characters of same class in a password  |
| enableipav2nontp  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Setup/Do not setup the NTP against the IPAv2 domain  |
| winbindtemplateprimarygroup  |   no  |  | |  the group which winbind-created users will have as their primary group  |
| enableldaptls  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable use of TLS with LDAP (RFC-2830)  |
| smartcardaction  |   no  |  | <ul> <li>Lock</li>  <li>Ignore</li> </ul> |  Specify action to be taken on smart card removal  |
| enablemd5  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable MD5 passwords by default  |
| passminclass  |   no  |  | |  Specify minimum number of character classes in a password  |
| winbindseparator  |   no  |  | |  Specify the character which will be used to separate the domain and user part of winbind-created user names if winbindusedefaultdomain is not enabled  |
| enableecryptfs  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable automatic per-user ecryptf  |
| nisserver  |   no  |  | <ul> <li>descrypt</li>  <li>bigcrypt</li>  <li>md5</li>  <li>sha256</li>  <li>sha512</li> </ul> |  Specify default NIS server  |


## Examples

```
# Configure LDAP
- authconfig: enableldap=yes enableldapauth=yes enableldaptls=no
              ldapserver=ldap://127.0.0.1/ ldapbasedn=dc=example,dc=com
# Enable cache (nscd) but don't start nscd daemon
- authconfig: enablecache=yes nostart=yes

```

## Return Values

| name | description | returned | type | sample |
| ---- |-------------| ---------|----- |------- |
| new_settings_lines | when `new_settings`  | when not check_mode  | list | ['caching is disabled', 'nss_files is always enabled', 'nss_compat is disabled', 'nss_db is disabled', 'nss_hesiod is disabled', ' hesiod LHS = ""', ' hesiod RHS = ""', 'nss_ldap is enabled', '...'] |
| new_settings | 'authconfig --test' output  | when not check_mode  | string | caching is disabled nss_files is always enabled nss_compat is disabled nss_db is disabled nss_hesiod is disabled hesiod LHS = "" hesiod RHS = "" nss_ldap is enabled ... |

## Notes

- THIS IS EARLY PREVIEW, THINGS MAY CHANGE

- Since changed behavior depends on _authconfig --test_

## License

GPLv3
