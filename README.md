
# Andible authconfig module

Manages system authentication resources with I(authconfig).

  * Requirements
  * Install
  * Synopsis
  * Options
  * Examples


---
## Requirements
* authconfig package

## Install

TBD.

## Synopsis
 Configurering system authentication resources with I(authconfig(8)).

## Options

| Parameter     | required    | default  | choices    | comments |
| ------------- |-------------| ---------|----------- |--------- |
| nostart  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  do not start/stop portmap, ypbind, and nscd  |
| enableshadow  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable shadowed passwords by default  |
| ldaploadcacert  |   no  |  | |  load CA certificate from the URL  |
| enablerfc2307bis  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable use of RFC-2307bis schema for LDAP user information lookups  |
| passalgo  |   no  |  | <ul> <li>descrypt</li>  <li>bigcrypt</li>  <li>md5</li>  <li>sha256</li>  <li>sha512</li> </ul> |  Specify hash/crypt algorithm for new passwords  |
| savebackup  |   no  |  | |  Save a backup of all configuration files  |
| enableldap  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable LDAP for user information by default  |
| enablecache  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable caching of user information by defaul  |
| ldapbasedn  |   no  |  | |  default LDAP base DN  |
| enablemkhomedir  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Create/Don't create home directories for users on their first login  |
| nisdomain  |   no  |  | |  Specify default NIS domain  |
| ldapserver  |   no  |  | |  default LDAP server hostname or URI  |
| restorelastbackup  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Restore the backup of configuration files saved before the previous configuration change  |
| enableldapauth  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable LDAP for authentication by default  |
| enableldaptls  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable use of TLS with LDAP (RFC-2830)  |
| enablemd5  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable MD5 passwords by default  |
| enablenis  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  Enable/Disable NIS for user information by default  |
| enableforcelegacy  |   no  |  | <ul> <li>yes</li>  <li>no</li> </ul> |  When set to **no**, use SSSD implicitly if it supports the configuration. Set to **yes** never use SSSD implicity.  |
| restorebackup  |   no  |  | |  Restore the backup of configuration files  |
| nisserver  |   no  |  | <ul> <li>descrypt</li>  <li>bigcrypt</li>  <li>md5</li>  <li>sha256</li>  <li>sha512</li> </ul> |  Specify default NIS server  |


 
## Examples

```
# Configure LDAP
- authconfig: enableldap=yes enableldapauth=yes enableldaptls=no
              ldapserver=ldap://127.0.0.1/ ldapbasedn=dc=example,dc=com
# Enable cache (nscd) but don't start nscd daemon
- authconfig: enablecache=yes nostart=yes

```



---


---
## License

MIT
