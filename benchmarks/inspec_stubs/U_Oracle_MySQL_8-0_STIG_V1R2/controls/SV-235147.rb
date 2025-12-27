control 'SV-235147' do
  title 'The MySQL Database Server 8.0 must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc 'To ensure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system. 

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following:

(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and 
(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', %q(Review MySQL Database Server 8.0 settings to determine whether organizational users are uniquely identified and authenticated when logging on/connecting to the system. 

Using SQL, search for external authentication plugins:
SELECT PLUGIN_NAME, PLUGIN_STATUS
       FROM INFORMATION_SCHEMA.PLUGINS
       WHERE PLUGIN_NAME LIKE '%ldap%' OR PLUGIN_NAME LIKE '%ldap%' OR PLUGIN_NAME LIKE '%pam%';

This listing will show what is enabled. 

In addition to MySQL password-based internal accounts, there is also support for external accounts:
Linux PAM (Pluggable Authentication Modules)
Windows Active Directory (only for Windows MySQL servers)
Native LDAP 
auth_socket

Review the configuration of the plugin; for link of accounts and permissions to organizational level, run this SQL:
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME LIKE 'auth%' ;

This will show external configuration setup for authentication using an organizational authentication source.

Review users using organizational authentication.  Review the "authentication_string" for proper mapping:
SELECT `user`.`Host`,
    `user`.`user`,
    `user`.`plugin`,
    `user`.`authentication_string`
    from mysql.user where plugin like 'auth%';

If organizational users are not uniquely identified and authenticated, this is a finding.

If accounts are determined to be shared, determine if they are directly accessible to end users. If so, this is a finding.)
  desc 'fix', "Configure MySQL Database Server 8.0 settings to uniquely identify and authenticate all organizational users who log on/connect to the system.

Remove user-accessible shared accounts and use individual user names. 

Configure applications to ensure successful individual authentication prior to shared account access. 

Ensure each user's identity is received and used in audit data in all relevant circumstances.

Install appropriate auth plugin, for example LDAP.
INSTALL PLUGIN authentication_ldap_sasl
  SONAME 'authentication_ldap_sasl.so';
INSTALL PLUGIN authentication_ldap_simple
  SONAME 'authentication_ldap_simple.so';

Configure
SET PERSIST authentication_ldap_sasl_server_host='127.0.0.1';
SET PERSIST authentication_ldap_sasl_bind_base_dn='dc=example,dc=com';
SET PERSIST authentication_ldap_simple_server_host='127.0.0.1';
SET PERSIST authentication_ldap_simple_bind_base_dn='dc=example,dc=com';

Create users with proper organizational mapping, for example:
CREATE USER 'betsy'@'localhost'
  IDENTIFIED WITH authentication_ldap_simple
  BY 'uid=betsy_ldap,ou=People,dc=example,dc=com';

Assign appropriate roles and grants."
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38366r623561_chk'
  tag severity: 'medium'
  tag gid: 'V-235147'
  tag rid: 'SV-235147r623563_rule'
  tag stig_id: 'MYS8-00-006100'
  tag gtitle: 'SRG-APP-000148-DB-000103'
  tag fix_id: 'F-38329r623562_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
