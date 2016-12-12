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
      - "Set to I(yes) to enable SSSD for user information by default with
        manually managed configuration. Set to I(no) disable SSSD for user
        information by default (still used for supported configurations)"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  enablesssdauth:
    description:
      - "Set to I(yes) to enable SSSD for authentication by default with
        manually managed configuration. Set to I(no) to disable SSSD for
        authentication by default (still used for supported configurations)"
    required: false
    choices: [ "yes", "no" ]
    default: null
    aliases: []

  enableforcelegacy:
    description:
      - "When set to I(no), use SSSD implicitly if it supports the
        configuration. Set to I(yes) never use SSSD implicity."
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
      - "When set to I(yes), local authorization is sufficient for local
        users. Set to I(no) to authorize local users also through remote
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
      - "Set to I(yes) to authenticate system accounts by network services.
        Set to I(no) to authenticate system accounts by local files only."
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

notes:
    - THIS IS EARLY PREVIEW, THINGS MAY CHANGE
    - "Since changed behavior depends on I(authconfig --test) output, this
      module reports not changed for some options even if changes are made"
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
RETURN = '''
new_settings:
    description: "'authconfig --test' output"
    returned: when not check_mode
    type: string
    sample: 'caching is disabled\nnss_files is always enabled\nnss_compat is disabled\nnss_db is disabled\nnss_hesiod is disabled\n hesiod LHS = ""\n hesiod RHS = ""\n nss_ldap is enabled\n...'
new_settings_lines:
    description: when C(new_settings) is returned we also provide this field which is a list of strings, one item per line from the original.
    returned: when not check_mode
    type: list
    sample: ["caching is disabled", "nss_files is always enabled", "nss_compat is disabled", "nss_db is disabled", "nss_hesiod is disabled", ' hesiod LHS = ""', ' hesiod RHS = ""', "nss_ldap is enabled", "..."]
'''

import re
from StringIO import StringIO
from ansible.module_utils.six import iteritems
import sys
try:
    sys.path.append('/usr/share/authconfig')
    from authconfig import Authconfig
    import authinfo
except ImportError:
    authconfig_found = False
else:
    authconfig_found = True


#class AnsibleAuthinfo(authconfig.Authinfo):
#    def diff(self, other):

class AnsibleAuthconfig(Authconfig, object):

    def __init__(self, module):
        super(AnsibleAuthconfig, self).__init__()
        self.ansible_module = module
        self.result = { 'warnings': [], 'rc': 0 }

    def module(self):
        return "ansible-authconfig"

    def printError(self, error):
        super(AnsibleAuthconfig, self).printError(error)
        self.result['warnings'].append("%s: %s\n" % (self.module(), error))

    def parseOptions(self):
        # building dummy argv
        argv = ['/usr/sbin/authconfig']
        if self.ansible_module.check_mode:
            argv.append('--test')
        else:
            argv.append('--update')

        for x in self.ansible_module.params:
            if self.ansible_module.params[x] is None:
                continue

            if 'type' in self.ansible_module.argument_spec[x] \
                   and self.ansible_module.argument_spec[x]['type'] == 'bool':
                if x in ['nostart', 'restorelastbackup']:
                    if self.ansible_module.params[x]:
                        argv.append('--'+x)
                else:
                   opt = '--' + x
                   if not self.ansible_module.params[x]:
                       opt = opt.replace('enable', 'disable', 1)
                   argv.append(opt)
            else:
                argv.extend(['--'+x, self.ansible_module.params[x]])

        try:
            try:
                # replace sys.argv with dummy to work OptionParser#parse_args()
                bk_argv   = sys.argv
                sys.argv   = argv
                super(AnsibleAuthconfig, self).parseOptions()
            except SystemError:
                e = get_exception()
                raise(e)
        finally:
            sys.argv   = bk_argv

def run_authconfig(authconfig):
    rc = -1

    bk_stdout = sys.stdout
    bk_stderr = sys.stderr
    sys.stdout = StringIO()
    sys.stderr = StringIO()

    try:
        try:
            rc = authconfig.run()
            # old Authconfig.run() has no return statement
            if rc is None:
                rc = 0
            authconfig.result['rc'] = rc
        except SystemExit:
            e = get_exception()
            if type(e.args[0]) is int:
                authconfig.result['rc'] = e.args[0]
            else:
                authconfig.result['rc'] = rc # -1
    finally:
        authconfig.result['stderr'] = sys.stderr.getvalue()
        authconfig.result['stdout'] = sys.stdout.getvalue()

        # which is better?
        # (a)
        #authconfig.result['warnings'] = authconfig.result['stderr'].splitlines()
        # (b)
        #for l in sys.stderr.getvalue().getlines():
        #    # add error messages written by other than authconfig to warnings
        #    if l not in authconfig.result['warnings']:
        #        authconfig.result['warnings'].append(s)
        sys.stderr = bk_stderr
        sys.stdout = bk_stdout

    if rc == -1:
        authconfig.result['msg'] = authconfig.result['stderr']
        #authconfig.ansible_module.fail_json(msg="\n".join(authconfig.result['warnings']), **authconfig.result)
        authconfig.ansible_module.fail_json(**authconfig.result)

    return (rc, authconfig.result['stdout'], authconfig.result['stderr'])

def main():
    # authconfig version: RH5=5.3.21/EL6=6.1.12/EL7=6.2.8
    module = AnsibleModule(
        argument_spec=dict(
            enableshadow=dict(required=False, default=None, type='bool'), # support 'useshadow' as alias?
            enablemd5=dict(required=False, default=None, type='bool'), # support 'usemd5' as alias?
            passalgo=dict(required=False, default=None, choices=['descrypt', 'bigcrypt', 'md5', 'sha256', 'sha512']), # FIXME: use authinfo.password_algorithms for choices
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
            smartcardaction=dict(required=False, default=None, choices=[0,1]), #0:Lock, 1:Ignore FIXME: use authinfo.getSmartcardActions() for choies
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
            smbrealm=dict(required=False, default=None, type='str',),
            smbservers=dict(required=False, default=None, type='str'),
            smbworkgroup=dict(required=False, default=None, type='str'),
            # idmaprange
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
        ),
        supports_check_mode=True
    )
    if not authconfig_found:
        module.fail_json(msg="the authconfig package is required")

    # Store current settings
    dummy = lambda: None
    setattr(dummy,'params',[])
    setattr(dummy,'check_mode',True)
    orig_conf = AnsibleAuthconfig(dummy)
    rc, out, err = run_authconfig(orig_conf)

    # 
    new_conf = AnsibleAuthconfig(module)
    rc, out, err = run_authconfig(new_conf)

    if module.check_mode:
        new_conf.result['new_settings'] = out
        orig_conf.info.update()
        new_conf.info.update()
        new_conf.result['changed'] = new_conf.info.differs(orig_conf.info) # use pristineinfo???
        # XXX: 'authconfig --test' output doesn't contain all options'
        # information.
        if module._diff:
            result['diff'] = {'before': orig_conf.result['stdout'],
                               'after': out}
    else:
        real_new_conf = AnsibleAuthconfig(dummy)
        rc, out, err = run_authconfig(real_new_conf)

        new_conf.result['new_settings'] = out
        orig_conf.info.update()
        real_new_conf.info.update()
        new_conf.result['changed'] = real_new_conf.info.differs(orig_conf.info) # use pristineinfo???

    if new_conf.result['rc'] == 0:
        module.exit_json(**new_conf.result)
    else:
        new_conf.result['msg'] = "\n".join(new_conf.result['warnings'])
        module.fail_json(**new_conf.result)

# import module snippets
from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()
