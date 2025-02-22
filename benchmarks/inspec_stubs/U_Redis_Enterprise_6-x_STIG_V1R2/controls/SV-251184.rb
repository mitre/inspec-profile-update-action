control 'SV-251184' do
  title 'Redis Enterprise DBMS must integrate with an organization-level authentication/access mechanism providing account management and automation for all users, groups, roles, and any other principals.'
  desc "Enterprise environments make account management for applications and databases challenging and complex. A manual process for account management functions adds the risk of a potential oversight or other error. Managing accounts for the same person in multiple places is inefficient and prone to problems with consistency and synchronization.

A comprehensive application account management process that includes automation helps to ensure that accounts designated as requiring attention are consistently and promptly addressed. 

Examples include, but are not limited to, using automation to act on multiple accounts designated as inactive, suspended, or terminated, or by disabling accounts located in non-centralized account stores, such as multiple servers. Account management functions can also include assignment of group or role membership; identifying account type; specifying user access authorizations (i.e., privileges); account removal, update, or termination; and administrative alerts. The use of automated mechanisms can include, for example: using email or text messaging to notify account managers when users are terminated or transferred; using the information system to monitor account usage; and using automated telephone notification to report atypical system account usage.

The DBMS must be configured to automatically use organization-level account management functions, and these functions must immediately enforce the organization's current account policy. 

Automation may be comprised of differing technologies that when placed together contain an overall mechanism supporting an organization's automated account management requirements."
  desc 'check', 'Redis Enterprise supports LDAP for access to the Redis Enterprise web UI. If all accounts are authenticated by the organization-level authentication/access mechanism and not by the DBMS, this is not a finding. LDAP can be checked by examining the process used during user login on the Redis web UI.

If any accounts are managed by Redis Enterprise, review the system documentation for justification and approval of these accounts. Compare the documented accounts with those found on the system.

If any Redis Enterprise-managed accounts exist that are not documented and approved, this is a finding.'
  desc 'fix', 'Integrate Redis Enterprise with LDAP to provide organization-level authentication/access mechanism and account management for all users, groups, roles, and any other principals.

For each DBMS-managed account that is not documented and approved, either transfer it to management by the external mechanism or document the need for it and obtain approval as appropriate.

To enable LDAP:
1. Import the saslauthd configuration.
2. Restart saslauthd service.
3. Configure LDAP users.

Configuring LDAP:
To provide the LDAP configuration information:
1. Edit the configuration file located at /etc/opt/redislabs/saslauthd.conf or the installation directory used during initial configuration.

2. Provide the following information associated with each variable:
- ldap_servers: the ldap servers that authenticate against and the port to use:
Port 389 is standardly used for unencrypted LDAP connections
Port 636 is standardly used for encrypted LDAP connections and is strongly recommended.
- Ldap_tls_cacert_file (optional): The path to the CA Certificates. This is required for encrypted LDAP connections only.
- ldap_filter: the filter used to search for users.
- ldap_bind_dn: The distinguished name for the user that will be used to authenticate to the LDAP server.
- ldap_password: The password used for the user specified in ldap_bind_dn

3. Import the saslauthd configuration into Redis Enterprise using the command below, which will distribute the configuration to all nodes in the cluster:
rladmin cluster config saslauthd_ldap_conf <path_to_saslauthd.conf>

Note: For this command to work on a new server installation, a cluster must be set up already.

4. Restart saslauthd:
sudo supervisorctl restart saslauthd'
  impact 0.7
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54619r804740_chk'
  tag severity: 'high'
  tag gid: 'V-251184'
  tag rid: 'SV-251184r804742_rule'
  tag stig_id: 'RD6X-00-000700'
  tag gtitle: 'SRG-APP-000023-DB-000001'
  tag fix_id: 'F-54573r804741_fix'
  tag 'documentable'
  tag cci: ['CCI-000015']
  tag nist: ['AC-2 (1)']
end
