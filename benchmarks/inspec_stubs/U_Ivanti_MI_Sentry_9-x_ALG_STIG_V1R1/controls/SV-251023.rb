control 'SV-251023' do
  title 'The Sentry providing mobile device access control intermediary services must be configured with a pre-established trust relationship and mechanisms with appropriate authorities (e.g., Active Directory or AAA server) which validate mobile device account access authorizations and privileges.'
  desc 'User account and privilege validation must be centralized in order to prevent unauthorized access using changed or revoked privileges.

ALGs can implement functions such as traffic filtering, authentication, access, and authorization functions based on computer and user privileges. However, the directory service (e.g., Active Directory or LDAP) must not be installed on the ALG, particularly if the gateway resides on the untrusted zone of the Enclave.'
  desc 'check', 'Verify the MobileIron Core configured with the MobileIron Sentry is enabled with Active Directory or LDAP server. 

1. Log in to the MobileIron Core MIFS portal.
2. Go to Services >> LDAP.
3. Verify an LDAP server is configured and enabled.

If an LDAP server is not configured and enabled, this is a finding.'
  desc 'fix', 'Ensure the MobileIron Core configured with the MobileIron Sentry is enabled with Active Directory or LDAP server. 

1. Log in to the MobileIron Core MIFS portal.
2. Go to Services >> LDAP.
3. Click "Add New".
4. Follow LDAP Configuration Wizard Prompts to enable an LDAP server (refer to the "Configuring LDAP Servers" section of the "Getting Started with MobileIron Core Guide" for more information).
5. Click "Save".'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x ALG'
  tag check_id: 'C-54458r802289_chk'
  tag severity: 'medium'
  tag gid: 'V-251023'
  tag rid: 'SV-251023r802291_rule'
  tag stig_id: 'MOIS-AL-000380'
  tag gtitle: 'SRG-NET-000138-ALG-000088'
  tag fix_id: 'F-54412r802290_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
