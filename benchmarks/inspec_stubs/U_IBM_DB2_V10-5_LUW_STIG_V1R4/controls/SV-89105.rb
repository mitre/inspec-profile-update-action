control 'SV-89105' do
  title 'DB2 must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.'
  desc "Enterprise environments make account management for applications and databases challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other error. Managing accounts for the same person in multiple places is inefficient and prone to problems with consistency and synchronization.

A comprehensive application account management process that includes automation helps to ensure that accounts designated as requiring attention are consistently and promptly addressed. 

Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended, or terminated, or by disabling accounts located in non-centralized account stores, such as multiple servers. Account management functions can also include: assignment of group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example: using email or text messaging to notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephone notification to report atypical system account usage.

The DBMS must be configured to automatically utilize organization-level account management functions, and these functions must immediately enforce the organization's current account policy. 

Automation may be comprised of differing technologies that when placed together contain an overall mechanism supporting an organization's automated account management requirements."
  desc 'check', 'The default name and location for the IBM LDAP security plug-in configuration file is:

On UNIX/LINUX: INSTHOME/sqllib/cfg/IBMLDAPSecurity.ini

On Windows: %DB2PATH%\\cfg\\IBMLDAPSecurity.ini

If the IBMLDAPSecurity.ini  file does not exist in the default location and environment variable DB2LDAPSecurityConfig  is not set, this is a finding. 

If the environment variable DB2LDAPSecurityConfig is set and file does not exist in DB2LDAPSecurityConfig location, this is a finding. 

Find the value of SRVCON_PW_PLUGIN by running 

     $db2 get dbm cfg

If SRVCON_PW_PLUGIN is not set to IBMLDAPauthserver, this is a finding. 

Note:
In Windows, find the location of base installation directory of DB2 using one of following methods
1. Find the value of DB2PATH variable using  db2set –all on DB2 CLP 
2. Run db2level command
3. Go to Registry Editor in Windows
     Computer >> HKEY_LOCAL_MACHINE >> SOFTWARE >> IBM >> DB2 >> installedCopies >> DB2COPY1
Then find the value of the DB2 Path Name'
  desc 'fix', "Create an IBMLDAPSecurity.ini file at the default name and location for the IBM LDAP security plug-in configuration file:

    On UNIX/LINUX:  $INSTHOME/sqllib/cfg/IBMLDAPSecurity.ini
    On Windows:  %DB2PATH%\\cfg\\IBMLDAPSecurity.ini

To create the file in a non-default location, set the environment variable DB2LDAPSecurityConfig to the directory name where configuration file IBMLDAPSecurity.ini is located. 

Set the value of SRVCON_PW_PLUGIN to IBMLDAPauthserver for instance by running the following command:

     $db2 update dbm cfg using SRVCON_PW_PLUGIN IBMLDAPauthserver immediate

Refer to details below to determine appropriate values in LDAP configuration file.

-- SERVER-RELATED values:
1) LDAP_HOST - The name of the LDAP server(s) - This is a space separated list of LDAP server host names or IP addresses, with an optional port number for each one. 

For example: host1[:port1] [host2:[port2] ... The default port number is 389, or 636 if SSL is enabled.

2) ENABLE_SSL - To enable SSL support, set ENABLE_SSL to TRUE (you must have the GSKit installed). This is an optional parameter; it defaults to FALSE (no SSL support).

3) SSL_KEYFILE - The path for the SSL keyring. A keyfile is only required if your LDAP server is using a certificate that is not automatically trusted by your GSKit installation. 

For example: SSL_KEYFILE = /home/db2inst1/IBMLDAPSecurity.kdb

4) SSL_PW - The SSL keyring password. For example: SSL_PW = keyfile-password

5) SECURITY_PROTOCOL - To enable TLS 1.2 support, set SECURITY_PROTOCOL to TLSV12. To enable TLS 1.0, 1.1, and 1.2 support, set SECURITY_PROTOCOL to ALL. 

By default, SECURITY_PROTOCOL is not set. This setting means TLS 1.2 is not supported.

-- USER_RELATED values:
1) USER_OBJECTCLASS - The LDAP object class used for users. 

Generally, set USER_OBJECTCLASS to inetOrgPerson (the user for Microsoft Active Directory) 

For example: USER_OBJECTCLASS = inetOrgPerson

2) USER_BASEDN -  The LDAP base DN to use when searching for users. If not specified, user searches start at the root of the LDAP directory. Some LDAP servers require that you specify a value for this parameter. 

For example: USER_BASEDN = o=ibm

3) USERID_ATTRIBUTE - The LDAP user attribute that represents the user ID. The USERID_ATTRIBUTE attribute is combined with the USER_OBJECTCLASS and USER_BASEDN (if specified) to construct an LDAP search filter when a user issues a DB2 CONNECT statement with an unqualified user ID. 

For example, if USERID_ATTRIBUTE = uid, then issuing this statement: db2 connect to MYDB user bob using bobpass results in the following search filter:
&(objectClass=inetOrgPerson)(uid=bob)

4) AUTHID_ATTRIBUTE - The LDAP user attribute that represents the DB2 authorization ID. Usually this is the same as the USERID_ATTRIBUTE.
For example: AUTHID_ATTRIBUTE = uid

-- GROUP-RELATED values: 
1) GROUP_OBJECTCLASS - The LDAP object class used for groups. Generally this is groupOfNames or groupOfUniqueNames
(for Microsoft Active Directory, it is group)

For example: GROUP_OBJECTCLASS = groupOfNames

2) GROUP_BASEDN - The LDAP base DN to use when searching for groups If not specified, group searches start at the root of the LDAP directory. Some LDAP servers require that you specify a value for this parameter.

For example: GROUP_BASEDN = o=ibm

3) GROUPNAME_ATTRIBUTE - The LDAP group attribute that represents the name of the group.

For example: GROUPNAME_ATTRIBUTE = cn

4) GROUP_LOOKUP_ METHOD - Determines the method used to find the group memberships for a user. 
Possible values are:
SEARCH_BY_DN Indicates to search for groups that list the user as a member. Membership is indicated by the group attribute defined as GROUP_LOOKUP_ATTRIBUTE (typically, member or uniqueMember). 

USER_ATTRIBUTE In this case, a user's groups are listed as attributes of the user object itself. This setting indicates to search for the user attribute defined as GROUP_LOOKUP_ATTRIBUTE to get the user's groups (typically memberOf for Microsoft Active Directory or ibm-allGroups for IBM Tivoli Directory Server).

For example: GROUP_LOOKUP_METHOD = SEARCH_BY_DN
GROUP_LOOKUP_METHOD = USER_ATTRIBUTE

5) GROUP_LOOKUP_ATTRIBUTE - Name of the attribute used to determine group membership, as described for GROUP_LOOKUP_METHOD.

For example:
GROUP_LOOKUP_ATTRIBUTE = member
GROUP_LOOKUP_ATTRIBUTE = ibm-allGroups
NESTED_GROUPS If NESTED_GROUPS is TRUE, the DB2 database manager recursively searches for group membership by attempting to look up the group memberships for every group that is found.

Cycles (such as A belongs to B, and B belongs to A) are handled correctly.
This parameter is optional, and defaults to FALSE.

-- MISCELLANEOUS  values:
1) SEARCH_DN, SEARCH_PW If your LDAP server does not support anonymous access, or if anonymous access is not sufficient when searching for users or groups, then you can optionally define a DN and password that will be used to perform searches.

For example:
SEARCH_DN = cn=root
SEARCH_PW = rootpassword

2) DEBUG  Set DEBUG to TRUE to write extra information to the db2diag log files to aid in debugging LDAP related issues.

Most of the additional information is logged at
DIAGLEVEL 4 (INFO).
DEBUG defaults to false."
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74357r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74431'
  tag rid: 'SV-89105r1_rule'
  tag stig_id: 'DB2X-00-000300'
  tag gtitle: 'SRG-APP-000023-DB-000001'
  tag fix_id: 'F-81031r4_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
