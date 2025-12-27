control 'SV-221169' do
  title 'If DBMS authentication using passwords is employed, MongoDB must enforce the DoD standards for password complexity and lifetime.'
  desc 'OS/enterprise authentication and identification must be used (SQL2-00-023600). Built-in DBMS authentication may be used only when circumstances make it unavoidable and must be documented and AO-approved.

The DoD standard for authentication is DoD-approved PKI certificates. Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

In such cases, the DoD standards for password complexity and lifetime must be implemented. DBMS products that can inherit the rules for these from the operating system or access control program (e.g., Microsoft Active Directory) must be configured to do so. For other DBMSs, the rules must be enforced using available configuration parameters or custom code.'
  desc 'check', 'If MongoDB is using Native LDAP authentication where the LDAP server is configured to enforce password complexity and lifetime, this is not a finding.

If MongoDB is using Kerberos authentication where Kerberos is configured to enforce password complexity and lifetime, this is not a finding.

If MongoDB is configured for SCRAM-SHA1, MONGODB-CR, LDAP Proxy authentication, this is a finding.

See: https://docs.mongodb.com/v3.4/core/authentication/#authentication-methods'
  desc 'fix', 'Either configure MongoDB for Native LDAP authentication where LDAP is configured to enforce password complexity and lifetime.
OR
Configure MongoDB Kerberos authentication where Kerberos is configured to enforce password complexity and lifetime.'
  impact 0.7
  ref 'DPMS Target MongoDB Enterprise Advanced 3.x'
  tag check_id: 'C-22884r411001_chk'
  tag severity: 'high'
  tag gid: 'V-221169'
  tag rid: 'SV-221169r822437_rule'
  tag stig_id: 'MD3X-00-000320'
  tag gtitle: 'SRG-APP-000164-DB-000401'
  tag fix_id: 'F-22873r411002_fix'
  tag 'documentable'
  tag legacy: ['SV-96579', 'V-81865']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
