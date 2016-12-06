#!/usr/bin/python -tt
# -*- coding: utf-8 -*-
#
# Copyright (C) 2016 KOICHIRO Kikuchi <koichiro at hataki.jp>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

# import os
import re

DOCUMENTATION = '''
---
module: authconfig
short_description: Manages system authentication resources with I(authconfig).
description:
     - Configurering system authentication resources with I(authconfig(8)).
options:
  enableshadow:
    description:
      - "Enable/Disable shadowed passwords by default"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  enablemd5:
    description:
      - "Enable/Disable MD5 passwords by default"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  passalgo:
    description:
      - "Specify hash/crypt algorithm for new passwords"
    required: false
    choices: [ "descrypt", "bigcrypt", "md5", "sha256", "sha512" ]
    default: null
    aliases: []

  enablenis:
    description:
      - "Enable/Disable NIS for user information by default"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  nisdomain:
    description:
      - "Specify default NIS domain"
    required: false
    default: null
    aliases: []

  nisserver:
    description:
      - "Specify default NIS server"
    required: false
    choices: [ "descrypt", "bigcrypt", "md5", "sha256", "sha512" ]
    default: null
    aliases: []

  enableldap:
    description:
      - "Enable/Disable LDAP for user information by default"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  enableldapauth:
    description:
      - "Enable/Disable LDAP for authentication by default"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  ldapserver:
    description:
      - "default LDAP server hostname or URI"
    required: false
    default: null
    aliases: []

  ldapbasedn:
    description:
      - "default LDAP base DN"
    required: false
    default: null
    aliases: []

  enableldaptls:
    description:
      - "Enable/Disable use of TLS with LDAP (RFC-2830)"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  enablerfc2307bis:
    description:
      - "Enable/Disable use of RFC-2307bis schema for LDAP user information
        lookups"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  ldaploadcacert:
    description:
      - "load CA certificate from the URL"
    required: false
    default: null
    aliases: []

  enableforcelegacy:
    description:
      - "When set to **no**, use SSSD implicitly if it supports the
        configuration. Set to **yes** never use SSSD implicity."
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  enablecache:
    description:
      - "Enable/Disable caching of user information by defaul"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  nostart:
    description:
      - "do not start/stop portmap, ypbind, and nscd"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  enablemkhomedir:
    description:
      - "Create/Don't create home directories for users on their first login"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  savebackup:
    description:
      - "Save a backup of all configuration files"
    required: false
    default: null
    aliases: []

  restorebackup:
    description:
      - "Restore the backup of configuration files"
    required: false
    default: null
    aliases: []

  restorelastbackup:
    description:
      - "Restore the backup of configuration files saved before the previous
         configuration change"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

author:
    - "KIKUCHI Koichiro"
'''
# Unsupported commands:
# --enablesmartcard/--disablesmartcard
#   disable authentication with smart card by default
#  --enablerequiresmartcard/--disablerequiresmartcard
#    require/do not require smart card for authentication by default
#  --smartcardmodule=<module>          default smart card module to use
#  --smartcardaction=<0=Lock|1=Ignore> action to be taken on smart card removal
# --enablekrb5/--disablekrb5
#   disable kerberos authentication by default
#  --krb5kdc=<server>      default kerberos KDC
#  --krb5adminserver=<server>  default kerberos admin server
#  --krb5realm=<realm>     default kerberos realm
#  --enablekrb5kdcdns/--disablekrb5kdcdns
#    disable use of DNS to find kerberos KDCs
#  --enablekrb5realmdns/--disablekrb5realmdns
#    disable use of DNS to find kerberos realms
# --enablewinbind/--disablewinbind
#   enable/disable winbind for user information by default
#  --enablewinbindauth/--disablewinbindauth
#   disable winbind for authentication by default
#  --smbsecurity=<user|server|domain|ads>
#   security mode to use for samba and winbind
#  --smbrealm=<realm>     default realm for samba and winbind when security=ads
#  --smbservers=<servers> names of servers to authenticate against
#  --smbworkgroup=<workgroup> workgroup authentication servers are in
#  --winbindseparator=<\>
#    the character which will be used to separate the domain and user part of
#    winbind-created user names if winbindusedefaultdomain is not enabled
#  --winbindtemplatehomedir=</home/%D/%U>
#    the directory which winbind-created users will have as home directories
#  --winbindtemplateprimarygroup=<nobody>
#    the group which winbind-created users will have as their primary group
#  --winbindtemplateshell=</bin/false>
#    the shell which winbind-created users will have as their login shell
#  --enablewinbindusedefaultdomain/--disablewinbindusedefaultdomain
#   configures winbind to assume that users with no domain in their user names
#   are domain/not domain users
#  --enablewinbindoffline/--disablewinbindoffline
#                        configures winbind to allow/prevent offline login
#  --smbidmapuid=<lowest-highest>, --smbidmapgid=<lowest-highest>
#                        uid range winbind will assign to domain or ads users
#  --winbindjoin=<Administrator>
#    join the winbind domain or ads realm now as this administrator
#    --enablewins            enable wins for hostname resolution
#    --disablewins           disable wins for hostname resolution
# --enablepreferdns  prefer dns over wins or nis for hostname resolution
# --disablepreferdns do not prefer dns over wins or nis for hostname resolution
#    --enablehesiod          enable hesiod for user information by default
#    --disablehesiod         disable hesiod for user information by default
#    --hesiodlhs=<lhs>       default hesiod LHS
#    --hesiodrhs=<rhs>       default hesiod RHS
# --enablesssd     enable SSSD for user information by default with manually
#                  managed configuration
# --disablesssd    disable SSSD for user information by default (still used
#                  for supported configurations)
#  --enablesssdauth        enable SSSD for authentication by default with
#                          manually managed configuration
#  --disablesssdauth       disable SSSD for authentication by default (still
#                          used for supported configurations)
#  --enablelocauthorize    local authorization is sufficient for local users
#  --disablelocauthorize
#                        authorize local users also through remote service
# --enablepamaccess       check access.conf during account authorization
# --disablepamaccess      do not check access.conf during account authorization
# --enablesysnetauth      authenticate system accounts by network services
# --disablesysnetauth     authenticate system accounts by local files only
#
# --updateall             update all configuration files
# --probe                 probe network for defaults and print them
# 
# Available EL6+:
#  --enablecachecreds/--disablecachecreds
#                 enable/disable caching of user credentials in SSSD by default
#  --enablefingerprint/--disablefingerprint
#             enable/disable authentication with fingerprint readers by default
# --enableipav2/--disableipav2
#       enable/disable IPAv2 for user information and authentication by default
# --ipav2domain=<domain>  the IPAv2 domain the system should be part of
# --ipav2realm=<realm>    the realm for the IPAv2 domain
# --ipav2server=<servers> the server for the IPAv2 domain
# --enableipav2nontp      do not setup the NTP against the IPAv2 domain
# --disableipav2nontp     setup the NTP against the IPAv2 domain (default)
# --ipav2join=<account>   join the IPAv2 domain as this account
#+--disableldapstarttls/+--enableldapstarttls
#+--restorebackup=<name> #+--restorelastbackup #+--savebackup=<name> 
# --smbidmaprange=<lowest-highest> 

# Available EL7+:
# --enableecryptfs/--disableecryptfs 
#   disable automatic per-user ecryptfs
# --enablewinbindkrb5/--disablewinbindkrb5
#   winbind will use Kerberos 5 to authenticate/the default authentication
#   method
# --passminlen=<number>     minimum length of a password
# --passminclass=<number>   minimum number of character classes in a password
# --passmaxrepeat=<number>  maximum number of same consecutive characters in a
#                             a password
# --passmaxclassrepeat=<number> maximum number of consecutive characters of
#                             same class in a password
# --enablereqlower       require at least one lowercase character in a password
# --disablereqlower      do not require lowercase characters in a password
# --enablerequpper       require at least one uppercase character in a password
# --disablerequpper      do not require uppercase characters in a password
# --enablereqdigit       require at least one digit in a password
# --disablereqdigit      do not require digits in a password
# --enablereqother       require at least one other character in a password
# --disablereqother      do not require other characters in a password
EXAMPLES = '''
# Configure LDAP
- authconfig: enableldap=yes enableldapauth=yes enableldaptls=no
              ldapserver=ldap://127.0.0.1/ ldapbasedn=dc=example,dc=com
# Enable cache (nscd) but don't start nscd daemon
- authconfig: enablecache=yes nostart=yes
'''

def build_boolean_option(params, key):
    return '--' + (key if params[key] else key.replace('enable', 'disable', 1))


def main():
    # authconfig version: RH5=5.3.21/EL6=6.1.12/EL7=6.2.8
    argument_spec = dict(
        enableshadow=dict(required=False, default=None, type='bool'),
        enablemd5=dict(required=False, default=None, type='bool'),
        passalgo=dict(required=False, default=None, choices=['descrypt', 'bigcrypt', 'md5', 'sha256', 'sha512']),
        enablenis=dict(required=False, default=None, type='bool'),
        nisdomain=dict(required=False, default=None),
        nisserver=dict(required=False, default=None),
        enableldap=dict(required=False, default=None, type='bool'),
        enableldapauth=dict(required=False, default=None, type='bool'),
        ldapserver=dict(required=False, default=None),
        ldapbasedn=dict(required=False, default=None),
        enableldaptls=dict(required=False, default=None, type='bool'),
        enablerfc2307bis=dict(required=False, default=None, type='bool', ver_added='6.1.0'),
        ldaploadcacert=dict(required=False, default=None, ver_added='5.3.19'),
        enableforcelegacy=dict(required=False, default=None, type='bool', ver_added='6.1.8'),
        enablemkhomedir=dict(required=False, default=None, type='bool', ver_added='5.3.19'),
        enablecache=dict(required=False, default=None, type='bool'),
        nostart=dict(required=False, default=None, type='bool'),
        savebackup=dict(required=False, default=None, ver_added='5.4.0'),
        restorebackup=dict(required=False, default=None, ver_added='5.4.0'),
        restorelastbackup=dict(required=False, default=None, type='bool', ver_added='5.4.0'),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True
    )

    params = module.params

    options = []
    result = dict(changed=False,msg="No options specified")

    authconfigbin = module.get_bin_path('authconfig')
    if authconfigbin is None:
        module.fail_json(msg='authconfig command not found')

    version_matcher = re.compile('(\d+)\.(\d+)\.(\d+)')
    rpmbin = module.get_bin_path('rpm')
    if rpmbin is None:
        module.fail_json(msg='rpm command not found')
    rc, out, err = module.run_command([rpmbin, '-q', 'authconfig'])
    authconfig_ver = version_matcher.search(out)

    def is_unsupported(option):
        if 'ver_added' not in argument_spec[x]:
            return False

        ver = version_matcher.match(argument_spec[x]['ver_added'])
        # check version
        if authconfig_ver.group(1) < ver.group(1) \
           or authconfig_ver.group(2) < ver.group(2) \
           or authconfig_ver.group(3) < ver.group(3):
            return True
        return False

    for x in params:
        if params[x] is None:
            continue

        if is_unsupported(x):
            msg='%s is unsupported by authconfig %s' % (x, authconfig_ver.group(0))
            result['warnings'].append(msg)
            module.fail_json(msg)

        if 'type' in argument_spec[x] and argument_spec[x]['type'] == 'bool':
            if x in {'nostart', 'restorelastbackup'}:
                if params[x]:
                    options.append('--'+x)
            else:
                options.append(build_boolean_option(params, x))
        else:
            options.extend(['--'+x, params[x]])

    if options:
        def run_authconfig(options,mode,allow_fail=False):
            cmd = [authconfigbin]
            cmd.extend(options)
            cmd.append('--'+mode)
            rc, out, err = module.run_command(cmd)

            if rc != 0 and not allow_fail:
                module.fail_json(msg='Failed executing command: '+" ".join(cmd),
                                 rc=rc, err=err)
            return (rc, out, err)

        rc, before, err = run_authconfig([], 'test')
        rc, after, err = run_authconfig(options, 'test')

        result['changed'] = before != after

        if module.check_mode:
            if module._diff:
                result['diff'] = {'before': before,
                                   'after': after}
            module.exit_json(**result)

        rc, out, err = run_authconfig(options, 'update', True)

        result['rc'] = rc
        if rc == 0:
            result['msg'] = "Auth configuration updated. options=" + ' '.join(options)
        else:
            result['msg'] = err
            rc, after, err = run_authconfig([], 'test', True)
            if rc == 0:
                result['changed'] = before != after
            module.fail_json(**result)

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()
