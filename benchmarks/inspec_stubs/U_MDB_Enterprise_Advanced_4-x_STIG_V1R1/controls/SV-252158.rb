control 'SV-252158' do
  title 'If passwords are used for authentication, MongoDB must implement LDAP or Kerberos for authentication to enforce the DoD standards for password complexity and lifetime.'
  desc 'OS/enterprise authentication and identification must be used (SRG-APP-000023-DB-000001). Native DBMS authentication may be used only when circumstances make it unavoidable, and must be documented and AO-approved.

The DoD standard for authentication is DoD-approved PKI certificates. Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

In such cases, the DoD standards for password complexity and lifetime must be implemented. DBMS products that can inherit the rules for these from the operating system or access control program (e.g., Microsoft Active Directory) must be configured to do so. For other DBMSs, the rules must be enforced using available configuration parameters or custom code.

For MongoDB, password complexity and lifetime requirements must be enforced by an external authentication source such as LDAP, Active Directory, or Kerberos.'
  desc 'check', 'If MongoDB is using Native LDAP authentication where the LDAP server is configured to enforce password complexity and lifetime, this is not a finding.

If MongoDB is using Kerberos authentication where Kerberos is configured to enforce password complexity and lifetime, this is not a finding.

If MongoDB is not configured for SCRAM-SHA1, MONGODB-CR, or LDAP authentication, this is a finding.'
  desc 'fix', 'Password complexity and lifetime must be enforced by an external authentication source such as LDAP, Active Directory, or Kerberos.

Information on configuring MongoDB for one of these authentication mechanisms be found here:

LDAP/Active Directory: 
https://docs.mongodb.com/v4.4/tutorial/authenticate-nativeldap-activedirectory/

Kerberos:
https://docs.mongodb.com/v4.4/tutorial/control-access-to-mongodb-with-kerberos-authentication/'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55614r813854_chk'
  tag severity: 'medium'
  tag gid: 'V-252158'
  tag rid: 'SV-252158r813856_rule'
  tag stig_id: 'MD4X-00-002950'
  tag gtitle: 'SRG-APP-000164-DB-000401'
  tag fix_id: 'F-55564r813855_fix'
  tag 'documentable'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
