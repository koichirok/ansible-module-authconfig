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

  enablesmartcard:
    description:
      - "Enable/Disable authentication with smart card by default"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  enablerequiresmartcard:
    description:
      - "Require/Do not require smart card for authentication by default"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  smartcardmodule:
    description:
      - "Specify default smart card module to use"
    required: false
    default: null
    aliases: []

  smartcardaction:
    description:
      - "Specify action to be taken on smart card removal"
    required: false
    choices: [ "Lock", "Ignore" ]
    default: null
    aliases: []

  enablefingerprint:
    description:
      - "Enable/Disable authentication with fingerprint readers by default"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  enableecryptfs:
    description:
      - "Enable/Disable automatic per-user ecryptf"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  enablekrb5:
    description:
      - "Enable/Disable kerberos authentication by default"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  krb5kdc:
    description:
      - "Specify default kerberos KDC"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  krb5adminserver:
    description:
      - "Specify default kerberos admin server"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  krb5realm:
    description:
      - "Specify default kerberos realm"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  enablekrb5kdcdns:
    description:
      - "Enable/Disable use of DNS to find kerberos KDCs"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  enablekrb5realmdns:
    description:
      - "Enable/Disable use of DNS to find kerberos realms"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  enablewinbind:
    description:
      - "Enable/Disable winbind for user information by default"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  enablewinbindauth:
    description:
      - "Enable/Disable winbind for authentication by default"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  smbsecurity:
    description:
      - "Specify security mode to use for samba and winbind"
    required: false
    choices: [ "user", "server", "domain", "ads" ]
    default: null
    aliases: []

  smbrealm:
    description:
      - "Specify default realm for samba and winbind when security=ads"
    required: false
    default: null
    aliases: []

  smbservers:
    description:
      - "Specify names of servers to authenticate against"
    required: false
    default: null
    aliases: []

  smbworkgroup:
    description:
      - "Specify workgroup authentication servers are in"
    required: false
    default: null
    aliases: []

  winbindseparator:
    description:
      - "Specify the character which will be used to separate the domain and
        user part of winbind-created user names if winbindusedefaultdomain is
        not enabled"
    required: false
    default: null
    aliases: []

  winbindtemplatehomedir:
    description:
      - "Specify the directory which winbind-created users will have as home
        directories"
    required: false
    default: null
    aliases: []

  winbindtemplateprimarygroup:
    description:
      - "the group which winbind-created users will have as their primary group"
    required: false
    default: null
    aliases: []

  winbindtemplateshell:
    description:
      - "Specify the shell which winbind-created users will have as their login
        shell"
    required: false
    default: null
    aliases: []

  enablewinbindusedefaultdomain:
    description:
      - "Configures winbind to assume that users with no domain in their user
        names are domain/not domain users"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  enablewinbindoffline:
    description:
      - "Configures winbind to allow/prevent offline login"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  enablewinbindkrb5:
    description:
      - "Winbind will use Kerberos 5 to authenticate/the default authentication
        method"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  winbindjoin:
    description:
      - "Specify administrator account to Join the winbind domain or ads realm now"
    required: false
    default: null
    aliases: []

  enableipav2:
    description:
      - "Enable/Disable IPAv2 for user information and authentication by
        default"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  ipav2domain:
    description:
      - "Specify the IPAv2 domain the system should be part of"
    required: false
    default: null
    aliases: []

  ipav2realm:
    description:
      - "Specify the realm for the IPAv2 domain"
    required: false
    default: null
    aliases: []

  ipav2server:
    description:
      - "Specify the server for the IPAv2 domain"
    required: false
    default: null
    aliases: []

  enableipav2nontp:
    description:
      - "Setup/Do not setup the NTP against the IPAv2 domain"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  ipav2join:
    description:
      - "Specify the account to join the IPAv2 domain"
    required: false
    default: null
    aliases: []

  enablewins:
    description:
      - "Enable/Disable wins for hostname resolution"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  enablepreferdns:
    description:
      - "Prefer/Do not prefer dns over wins or nis for hostname resolution"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  enablehesiod:
    description:
      - "Enable/Disable hesiod for user information by default"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  hesiodlhs:
    description:
      - "Specify default hesiod LHS"
    required: false
    default: null
    aliases: []

  hesiodrhs:
    description:
      - "Specify default hesiod RHS"
    required: false
    default: null
    aliases: []

  enablesssd:
    description:
      - "Set to C(yes) to enable SSSD for user information by default with
        manually managed configuration. Set to C(no) disable SSSD for user
        information by default (still used for supported configurations)"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  enablesssdauth:
    description:
      - "Set to C(yes) to enable SSSD for authentication by default with
        manually managed configuration. Set to C(no) to disable SSSD for
        authentication by default (still used for supported configurations)"
    required: false
    choices: [ "yes", "no" ]
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

  enablecachecreds:
    description:
      - "Enable/Disable caching of user credentials in SSSD by default"
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

  enablelocauthorize:
    description:
      - "When set to C(yes), local authorization is sufficient for local
        users. Set to C(no) to authorize local users also through remote
        service"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  enablepamaccess:
    description:
      - "Check/Do not check access.conf during account authorization"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  enablesysnetauth:
    description:
      - "Set to C(yes) to authenticate system accounts by network services.
        Set to C(no) to authenticate system accounts by local files only."
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

  passminlen:
    description:
      - "Specify minimum length of a password"
    required: false
    default: null
    aliases: []

  passminclass:
    description:
      - "Specify minimum number of character classes in a password"
    required: false
    default: null
    aliases: []

  passmaxrepeat:
    description:
      - "Specify maximum number of same consecutive characters in a password"
    required: false
    default: null
    aliases: []

  passmaxclassrepeat:
    description:
      - "Specify maximum number of consecutive characters of same class in a password"
    required: false
    default: null
    aliases: []

  enablereqlower:
    description:
      - "Require at least one lowercase character/Do not require lowercase
        characters in a password"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  enablerequpper:
    description:
      - "Require at least one uppercase character/Do not require uppercase
        characters in a password"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  enablereqdigit:
    description:
      - "Require at least one digit/Do not require digits in a password"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  enablereqother:
    description:
      - "Require at least one other character/Do not require other characters in a password"
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
# Currently unsupported commands:
# * --smbidmapuid=<lowest-highest>, --smbidmapgid=<lowest-highest>,
#   --smbidmaprange=<lowest-highest> (available EL6+)
# * --disableldapstarttls/--enableldapstarttls (available EL6+)
EXAMPLES = '''
# Configure LDAP
- authconfig: enableldap=yes enableldapauth=yes enableldaptls=no
              ldapserver=ldap://127.0.0.1/ ldapbasedn=dc=example,dc=com
# Enable cache (nscd) but don't start nscd daemon
- authconfig: enablecache=yes nostart=yes
'''

def build_boolean_option(params, key):
    opt = '--'
    if params[key]:
        opt += key
    else:
        opt += key.replace('enable', 'disable', 1)
    return opt


def main():
    # authconfig version: RH5=5.3.21/EL6=6.1.12/EL7=6.2.8
    argspec = dict(
        enableshadow=dict(required=False, default=None, type='bool'), # support 'useshadow' as alias?
        enablemd5=dict(required=False, default=None, type='bool'), # support 'usemd5' as alias?
        passalgo=dict(required=False, default=None, choices=['descrypt', 'bigcrypt', 'md5', 'sha256', 'sha512']),
        enablenis=dict(required=False, default=None, type='bool'),
        nisdomain=dict(required=False, default=None, type='str'),
        nisserver=dict(required=False, default=None, type='str'),
        enableldap=dict(required=False, default=None, type='bool'),
        enableldapauth=dict(required=False, default=None, type='bool'),
        ldapserver=dict(required=False, default=None, type='str'),
        ldapbasedn=dict(required=False, default=None, type='str'),
        enableldaptls=dict(required=False, default=None, type='bool'),
        enablerfc2307bis=dict(required=False, default=None, type='bool'),
        ldaploadcacert=dict(required=False, default=None),
        enablesmartcard=dict(required=False, default=None, type='bool'),
        enablerequiresmartcard=dict(required=False, default=None, type='bool'),
        smartcardmodule=dict(required=False, default=None, type='str'),
        smartcardaction=dict(required=False, default=None, choices=['Lock','Ignore']),
        enablefingerprint=dict(required=False, default=None, type='bool'),
        enableecryptfs=dict(required=False, default=None, type='bool'),
        enablekrb5=dict(required=False, default=None, type='bool'),
        krb5kdc=dict(required=False, default=None, type='str'),
        krb5adminserver=dict(required=False, default=None, type='str'),
        krb5realm=dict(required=False, default=None, type='str'),
        enablekrb5kdcdns=dict(required=False, default=None, type='bool'),
        enablekrb5realmdns=dict(required=False, default=None, type='bool'),
        enablewinbind=dict(required=False, default=None, type='bool'),
        enablewinbindauth=dict(required=False, default=None, type='bool'),
        smbsecurity=dict(required=False, default=None, choices=['user', 'server', 'domain', 'ads']),
        smbrealm=dict(required=False, default=None, type='str'),
        smbservers=dict(required=False, default=None, type='str'),
        smbworkgroup=dict(required=False, default=None, type='str'),
        winbindseparator=dict(required=False, default=None, type='str'),
        winbindtemplatehomedir=dict(required=False, default=None, type='str'),
        winbindtemplateprimarygroup=dict(required=False, default=None, type='str'),
        winbindtemplateshell=dict(required=False, default=None, type='str'),
        enablewinbindusedefaultdomain=dict(required=False, default=None, type='bool'),
        enablewinbindoffline=dict(required=False, default=None, type='bool'),
        enablewinbindkrb5=dict(required=False, default=None, type='bool'),
        winbindjoin=dict(required=False, default=None, type='str'),
        enableipav2=dict(required=False, default=None, type='bool'),
        ipav2domain=dict(required=False, default=None, type='str'),
        ipav2realm=dict(required=False, default=None, type='str'),
        ipav2server=dict(required=False, default=None, type='str'),
        enableipav2nontp=dict(required=False, default=None, type='bool'),
        ipav2join=dict(required=False, default=None, type='str'),
        enablewins=dict(required=False, default=None, type='bool'),
        enablepreferdns=dict(required=False, default=None, type='bool'),
        enablehesiod=dict(required=False, default=None, type='bool'),
        hesiodlhs=dict(required=False, default=None, type='str'),
        hesiodrhs=dict(required=False, default=None, type='str'),
        enablesssd=dict(required=False, default=None, type='bool'),
        enablesssdauth=dict(required=False, default=None, type='bool'),
        enableforcelegacy=dict(required=False, default=None, type='bool'),
        enablecachecreds=dict(required=False, default=None, type='bool'),
        enablecache=dict(required=False, default=None, type='bool'),
        enablelocauthorize=dict(required=False, default=None, type='bool'),
        enablepamaccess=dict(required=False, default=None, type='bool'),
        enablesysnetauth=dict(required=False, default=None, type='bool'),
        enablemkhomedir=dict(required=False, default=None, type='bool'),
        passminlen=dict(required=False, default=None, type='int'),
        passminclass=dict(required=False, default=None, type='int'),
        passmaxrepeat=dict(required=False, default=None, type='int'),
        passmaxclassrepeat=dict(required=False, default=None, type='int'),
        enablereqlower=dict(required=False, default=None, type='bool'),
        enablerequpper=dict(required=False, default=None, type='bool'),
        enablereqdigit=dict(required=False, default=None, type='bool'),
        enablereqother=dict(required=False, default=None, type='bool'),
        nostart=dict(required=False, default=None, type='bool'),
        savebackup=dict(required=False, default=None, type='str'),
        restorebackup=dict(required=False, default=None, type='str'),
        restorelastbackup=dict(required=False, default=None, type='bool'),
    )

    module = AnsibleModule(
        argument_spec=argspec,
        supports_check_mode=True
    )

    params = module.params

    options = []
    result = dict(changed=False,msg="No options specified",warnings=[])

    authconfigbin = module.get_bin_path('authconfig')
    if authconfigbin is None:
        module.fail_json(msg='authconfig command not found')

    def run_authconfig(mode='test', options=[], allow_fail=False):
        cmd = [authconfigbin]
        cmd.extend(options)
        cmd.append('--'+mode)
        rc, out, err = module.run_command(cmd)

        if rc != 0 and not allow_fail:
            module.fail_json(msg='Failed executing command: '+" ".join(cmd),
                             rc=rc, err=err)
        return (rc, out, err)

    # Get available options from 'authconfig --help' output.
    # If each RPM package version of authconfig's supported options list is
    # available, we should use it.
    rc, out, err = run_authconfig('help')
    available_opts = {}
    for x in out.splitlines():
        x = x.strip()
        if not x.startswith('--'):
            continue
        x = re.sub(r'   *.*$','', x) # remove description
        for opt in x.split(', '):
            # skip --disable* options
            if opt.startswith('--disable'):
                continue
            # remove '=<...>' part
            if '=' in opt:
                opt = opt.split('=')[0]
            available_opts[opt.replace('--', 1)] = 1

    for x in params:
        if params[x] is None:
            continue

        if x not in available_opts:
            result['msg']='%s is unsupported by your authconfig version' % x
            # add option so as not to fail here?
            module.fail_json(**result)

        if 'type' in argspec[x] and argspec[x]['type'] == 'bool':
            if x in ['nostart', 'restorelastbackup']:
                if params[x]:
                    options.append('--'+x)
            else:
                options.append(build_boolean_option(params, x))
        else:
            options.extend(['--'+x, params[x]])

    if options:
        # Get current settings
        rc, before, err = run_authconfig()

        if module.check_mode:
            rc, out, err = run_authconfig('test', options)
            result['changed'] = before != out
            if module._diff:
                result['diff'] = {'before': before,
                                   'after': out}
            module.exit_json(**result)

        # Update settings
        rc, out, err = run_authconfig('update', options, True)
        result['rc'] = rc
        result['stdout'] = out
        result['stderr'] = err

        result['warnings'] = []
        for x in err.splitlines():
            if x not in ['getsebool:  SELinux is disabled',
                         'domainname: you must be root to change the domain name']:
                result['warnings'].append(x)

        # Get new settings here since some settings aren't changed if dependent
        # tools not installed.(e.g. nss-pam-ldapd, nscd, etc)
        rc, out, err = run_authconfig('test', [], True)
        result['new_settings'] = out
        result['new_settings_lines'] = out.splitlines()
        result['changed'] = before != out

        if result['rc'] == 0:
            result['msg'] = "Auth configuration updated."
        else:
            result['msg'] = "\n".join(result['warnings'])
            module.fail_json(**result)

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()
