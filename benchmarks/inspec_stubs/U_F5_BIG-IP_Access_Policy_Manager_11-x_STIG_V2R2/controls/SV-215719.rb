control 'SV-215719' do
  title 'The BIG-IP APM module must be configured with a pre-established trust relationship and mechanisms with appropriate authorities (e.g., Active Directory or authentication, authorization, and accounting (AAA) server) that validate user account access authorizations and privileges when providing access control to virtual servers.'
  desc 'User account and privilege validation must be centralized in order to prevent unauthorized access using changed or revoked privileges.

ALGs can implement functions such as traffic filtering, authentication, access, and authorization functions based on computer and user privileges. However, the directory service (e.g., Active Directory or LDAP) must not be installed on the ALG, particularly if the gateway resides on the untrusted zone of the Enclave.'
  desc 'check', 'If the BIG-IP APM module does not provide user access control intermediary services, this is not applicable.

Verify the BIG-IP APM module is configured as follows:

Navigate to the BIG-IP System manager >> Access Policy >> Access Profiles.

Click "Edit..." in the "Access Policy" column for an Access Profile used for granting access.

Verify the Access Profile is configured with a pre-established trust relationship and mechanisms with appropriate authorities (e.g., Active Directory or AAA server) that validate user account access authorizations and privileges.

If the BIG-IP APM is not configured with a pre-established trust relationship and mechanisms with appropriate authorities that validate each user access authorization and privileges, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure an access policy in the BIG-IP APM module with a pre-established trust relationship and mechanisms with appropriate authorities that validate each user access authorization and privileges.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Access Policy Manager 11.x'
  tag check_id: 'C-16912r290403_chk'
  tag severity: 'medium'
  tag gid: 'V-215719'
  tag rid: 'SV-215719r557355_rule'
  tag stig_id: 'F5BI-AP-000075'
  tag gtitle: 'SRG-NET-000138-ALG-000088'
  tag fix_id: 'F-16910r290404_fix'
  tag 'documentable'
  tag legacy: ['SV-74459', 'V-60029']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
