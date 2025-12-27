control 'SV-253667' do
  title 'MariaDB must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.'
  desc 'Enterprise environments make account management for applications and databases challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other error. Managing accounts for the same person in multiple places is inefficient and prone to problems with consistency and synchronization.

A comprehensive application account management process that includes automation helps to ensure that accounts designated as requiring attention are consistently and promptly addressed. 

Examples include, but are not limited to, using automation to take action on multiple accounts designated as inactive, suspended, or terminated, or by disabling accounts located in noncentralized account stores, such as multiple servers. Account management functions can also include assignment of group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example: using email or text messaging to notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephone notification to report atypical system account usage.

MariaDB must be configured to automatically utilize organization-level account management functions, and these functions must immediately enforce the organizations current account policy. 

Automation may be comprised of differing technologies that when placed together contain an overall mechanism supporting an organizations automated account management requirements.'
  desc 'check', "If all accounts are authenticated by the organization-level authentication/access mechanism such as LDAP, Kerberos, Active Directory and not by MariaDB, this is not a finding.

If there are any accounts managed by the DBMS, review the system documentation for justification and approval of these accounts.

If any DBMS-managed accounts exist that are not documented and approved, this is a finding.

As the OS administrator, review the configuration files /etc/pam.d and /etc/pam.conf. If file is missing or not configured, this is a finding. Example for LDAP authentication and authorization via PAM would be /etc/pam.d/mariadb_ldap: 

#############################
auth         required     pam_ldap.so
account    required     pam_ldap.so
#############################

Verify that PAM is by installed the following SQL:

MariaDB> SHOW PLUGINS;

If pam is not listed as active, this is a finding.

To find users not using PAM plugin for authentication: 

MariaDB> SELECT user, host, plugin FROM mysql.user WHERE plugin != 'pam';

If any users are returned, this is a finding."
  desc 'fix', "Integrate MariaDB security with an organization-level authentication/access mechanism providing account management for all users, groups, roles, and any other principals.

As the database administrator, install and configure the PAM authentication module:

MariaDB> INSTALL SONAME 'auth_pam';

PAM supports many authentication methods including LDAP, Active Directory, and Kerberos. Each method must be configured properly in /etc/pam.d and /etc/pam.conf. 

To alter non-PAM authenticated users to using PAM:

MariaDB> ALTER USER 'username'@'host' IDENTIFIED VIA pam USING mariadb_ldap;"
  impact 0.7
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57119r841524_chk'
  tag severity: 'high'
  tag gid: 'V-253667'
  tag rid: 'SV-253667r841526_rule'
  tag stig_id: 'MADB-10-000200'
  tag gtitle: 'SRG-APP-000023-DB-000001'
  tag fix_id: 'F-57070r841525_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
