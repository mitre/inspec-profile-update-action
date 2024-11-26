control 'SV-235095' do
  title 'MySQL Database Server 8.0 must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.'
  desc "Enterprise environments make account management for applications and databases challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other error. Managing accounts for the same person in multiple places is inefficient and prone to problems with consistency and synchronization.

A comprehensive application account management process that includes automation helps to ensure accounts designated as requiring attention are consistently and promptly addressed. 

Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended, or terminated, or by disabling accounts located in non-centralized account stores, such as multiple servers.  Account management functions can also include: assignment of group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example: using email or text messaging to notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephone notification to report atypical system account usage.

The DBMS must be configured to automatically utilize organization-level account management functions, and these functions must immediately enforce the organization's current account policy. 

Automation may be comprised of differing technologies that when placed together contain an overall mechanism supporting an organization's automated account management requirements."
  desc 'check', %q(Determine if an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals has been configured.

To determine if a MySQL Server has any external authentication plugins, connect as a mysql administrator (root) and run the following query: 
SELECT PLUGIN_NAME, PLUGIN_STATUS
       FROM INFORMATION_SCHEMA.PLUGINS
       WHERE PLUGIN_NAME LIKE '%ldap%' OR PLUGIN_NAME LIKE '%pam%' OR PLUGIN_NAME LIKE '%authentication_windows %';

One or more of the following plugins must be installed and in the listed results:
authentication_ldap_simple
authentication_ldap_sasl
authentication_pam
authentication_windows

If at least one of the above plugins is not installed, then no organization-level authentication/access is in place, and this is a finding.

Depending on the plugin in use, review its configuration.  

For a list of global variables, run the following query:
SELECT VARIABLE_NAME, VARIABLE_VALUE
FROM performance_schema.global_variables
WHERE VARIABLE_NAME LIKE 'auth%' ;  

If the LDAP plugin is installed, check the ldap_host and mapping. 

For the LDAP plugin, global variables showing the configuration for authentication to ldap hosts and binding to organizational users should look similar to the following:
authentication_ldap_simple_server_host=127.0.0.1
authentication_ldap_simple_bind_base_dn="dc=example,dc=com"
authentication_ldap_sasl_server_host=127.0.0.1
authentication_ldap_sasl_bind_base_dn="dc=example,dc=com"

If the ldap_host is not a valid authentication host or the mapping to the base_dn maps is not correct, this is a finding.

Determine the accounts (SQL Logins) managed by PAM. Run the statement: 
SELECT `user`.`Host`,
    `user`.`user`,
    `user`.`plugin`,
    `user`.`authentication_string`
    from mysql.user where plugin like 'authentication_pam';

For PAM, the string consists of a PAM service name, optionally followed by a PAM group mapping list consisting of one or more keyword/value pairs each specifying a PAM group name and a MySQL user name. 

If not defined, this is a finding.

If the windows plugin is installed, the organization mapping details will be defined within the user "authentication string". 

Determine the accounts (SQL logins) managed by Windows. Run the statement: 
Review the accounts
SELECT `user`.`Host`,
    `user`.`user`,
    `user`.`plugin`,
    `user`.`authentication_string`
    from mysql.user where plugin like 'authentication_windows;

Verify that the Windows user, group, and windows role in the authentication_string map to proper organizational users. If not, this is a finding.

To determine the accounts (MySQL accounts) actually managed by MySQL Server. Run the statement: 
SELECT `user`.`Host`,
    `user`.`User`,
    `user`.`plugin`,
    `user`.`authentication_string`
    from mysql.user where plugin not like 'auth%' and `user`.`User` not like 'mysql.%';

If any accounts listed by the query are not listed in the documentation and authorized, this is a finding.)
  desc 'fix', "Integrate MySQL database server 8.0 security with an organization-level authentication/access mechanism using MySQL external authentication for Microsoft AD or LDAP, or Linux PAMs thus providing account management for all users, groups, roles, and any other principals.

If native mysql users are required, document the need and justification; describe the measures taken to ensure the use of MySQL Server authentication is kept to a minimum; describe the measures taken to safeguard passwords; list or describe the MySQL logins used.

For each MySQL database server 8.0 managed account that is not documented and approved, either transfer it to management by the external mechanism, or document the need for it and obtain approval, as appropriate. 

Install appropriate external authentication plugin, for example to install LDAP.     
INSTALL PLUGIN authentication_ldap_sasl
  SONAME 'authentication_ldap_sasl.so';
INSTALL PLUGIN authentication_ldap_simple
  SONAME 'authentication_ldap_simple.so';

Configure the plugin, for example:
SET PERSIST authentication_ldap_sasl_server_host='127.0.0.1';
SET PERSIST authentication_ldap_sasl_bind_base_dn='dc=example,dc=com';
SET PERSIST authentication_ldap_simple_server_host='127.0.0.1';
SET PERSIST authentication_ldap_simple_bind_base_dn='dc=example,dc=com';

Create users with proper organizational mapping, for example:
CREATE USER 'betsy'@'localhost'
  IDENTIFIED WITH authentication_ldap_simple
  BY 'uid=betsy_ldap,ou=People,dc=example,dc=com';

Assign appropriate permissions via grants on objects or to roles, etc. See  https://dev.mysql.com/doc/refman/8.0/en/grant.html.
For example:
GRANT ALL ON db1.* TO 'betsy'@'localhost';
GRANT 'role1', 'role2' TO 'user1'@'localhost', 'user2'@'localhost';
GRANT SELECT ON world.* TO 'role3';

For accounts not required in the MySQL Server:
DROP USER <user_name>;"
  impact 0.7
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38314r623405_chk'
  tag severity: 'high'
  tag gid: 'V-235095'
  tag rid: 'SV-235095r638812_rule'
  tag stig_id: 'MYS8-00-000100'
  tag gtitle: 'SRG-APP-000023-DB-000001'
  tag fix_id: 'F-38277r623406_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
