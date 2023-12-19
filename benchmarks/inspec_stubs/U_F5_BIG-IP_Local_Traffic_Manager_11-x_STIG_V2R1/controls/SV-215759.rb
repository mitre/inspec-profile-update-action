control 'SV-215759' do
  title 'The BIG-IP Core implementation must be configured with a pre-established trust relationship and mechanisms with appropriate authorities (e.g., Active Directory or authentication, authorization, and accounting (AAA) server) that validate user account access authorizations and privileges when providing access control to virtual servers.'
  desc 'User account and privilege validation must be centralized in order to prevent unauthorized access using changed or revoked privileges.

ALGs can implement functions such as traffic filtering, authentication, access, and authorization functions based on computer and user privileges. However, the directory service (e.g., Active Directory or LDAP) must not be installed on the ALG, particularly if the gateway resides on the untrusted zone of the Enclave.'
  desc 'check', 'If the BIG-IP Core does not provide user access control intermediary services for virtual servers, this is not applicable.

When user access control intermediary services are provided, verify the BIG-IP Core is configured an APM policy with a pre-established trust relationship and mechanisms with appropriate authorities that validate each user access authorization and privileges.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Verify under "Access Policy" section, that "Access Policy" has been set to use an APM access policy that has been configured with a pre-established trust relationship and mechanisms with appropriate authorities that validate each user access authorization and privileges.

If the BIG-IP Core is not configured with a pre-established trust relationship and mechanisms with appropriate authorities that validate each user access authorization and privileges, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the BIG-IP Core as follows: 

Configure a policy in the BIG-IP APM module with a pre-established trust relationship and mechanisms with appropriate authorities that validate each user access authorization and privileges.

Apply the APM policy to the applicable Virtual Server(s) in the BIG-IP LTM module to validate user account access authorizations and privileges when providing access control to virtual servers.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16951r291090_chk'
  tag severity: 'medium'
  tag gid: 'V-215759'
  tag rid: 'SV-215759r557356_rule'
  tag stig_id: 'F5BI-LT-000075'
  tag gtitle: 'SRG-NET-000138-ALG-000088'
  tag fix_id: 'F-16949r291091_fix'
  tag 'documentable'
  tag legacy: ['SV-74729', 'V-60299']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
