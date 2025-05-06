control 'SV-251428' do
  title 'If DBMS authentication using passwords is employed, Redis Enterprise DBMS must enforce the DoD standards for password complexity and lifetime.'
  desc 'OS/enterprise authentication and identification must be used (SRG-APP-000023-DB-000001). Native DBMS authentication may be used only when circumstances make it unavoidable and must be documented and AO-approved.

The DoD standard for authentication is DoD-approved PKI certificates. Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

In such cases, the DoD standards for password complexity and lifetime must be implemented. DBMS products that can inherit the rules for these from the operating system or access control program (e.g., Microsoft Active Directory) must be configured to do so. For other DBMSs, the rules must be enforced using available configuration parameters or custom code.'
  desc 'check', 'Redis Enterprise Software supports Lightweight Directory Access Protocol (LDAP) admin console users. LDAP must be enabled to enforce password complexity. If LDAP is not in use, a password complexity profile can be configured in Redis Enterprise; however, it currently does not meet the DoD standard.

Review the LDAP settings relating to password complexity. To check the LDAP settings:
1. Log in to the server housing the Redis Enterprise as an admin user.
2. CAT /etc/opt/redislabs/saslauthd.conf or the installation choice used during initial configuration.
3. Verify the following is configured: 
ldap_servers
Ldap_tls_cacert_file
ldap_filter
ldap_bind_dn
ldap_password

If LDAP cannot be configured, this check can be downgraded if the password complexity profile has been configured:
- At least eight characters
- At least one uppercase character
- At least one lowercase character
- At least one number (not first or last character)
- At least one special character (not first or last character)

In addition, the password:
- Cannot contain the user ID or reverse of the user ID
- Cannot have more than three repeating characters

To verify this, either attempt a password change or view the password complexity settings in the REST API.

If LDAP or the password complexity profile is not in use, this is a finding.'
  desc 'fix', %q(Configure LDAP/AD to enforce password complexity.

To enable LDAP:
1. Import the saslauthd configuration.
2. Restart saslauthd service.
3. Configure LDAP users.

To provide the LDAP configuration information:
1. Edit the configuration file located at /etc/opt/redislabs/saslauthd.conf or the installation directory used during initial configuration.

2. Provide the following information associated with each variable:
ldap_servers: the ldap servers that authenticate against and the port to use
- Port 389 is standardly used for unencrypted LDAP connections.
- Port 636 is standardly used for encrypted LDAP connections and is strongly recommended.
- Ldap_tls_cacert_file: The path to the CA Certificates. This is required for encrypted LDAP connections only.
- ldap_filter: the filter used to search for users.
- ldap_bind_dn: The distinguished name for the user that will be used to authenticate to the LDAP server.
- ldap_password: The password used for the user specified in ldap_bind_dn.

3. Import the saslauthd configuration into Redis Enterprise using the command below, which will distribute the configuration to all nodes in the cluster:
rladmin cluster config saslauthd_ldap_conf <path_to_saslauthd.conf>

Note: For this command to work on a new server installation, a cluster must be set up already.

4. Restart saslauthd:
sudo supervisorctl restart saslauthd

An example configuration for reference may be found below:
ldap_servers: ldaps://ldap1.mydomain.com:636 ldap://ldap2.mydomain.com:636
ldap_tls_cacert_file: /path/to/the/CARootCert.crt
ldap_search_base: ou=coolUsers,dc=company,dc=com
ldap_search_base: ou=coolUsers,dc=company,dc=com
ldap_filter: (sAMAccountName=%u)
ldap_bind_dn: cn=admin,dc=company,dc=com
ldap_password: secretSquirrel

To set up an LDAP user, select an external account type when configuring the user following the procedure to configure users.

If LDAP cannot be configured, configure the password complexity profile. To enable the password complexity profile, run the following curl command against the REST API:
curl -k -X PUT -v -H "cache-control: no-cache" -H "content-type: application/json" -u "<administrator-user-email>:<password>" -d '{"password_complexity":true}' https://<RS_server_address>:9443/v1/cluster
To disable the password complexity requirement, run the same command, but set "password_complexity" to "false".)
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54863r806497_chk'
  tag severity: 'medium'
  tag gid: 'V-251428'
  tag rid: 'SV-251428r806500_rule'
  tag stig_id: 'RD6X-00-008750'
  tag gtitle: 'SRG-APP-000164-DB-000401'
  tag fix_id: 'F-54817r806498_fix'
  tag 'documentable'
  tag legacy: ['SV-75897', 'V-61407']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
