control 'SV-85975' do
  title 'The CA API Gateway providing user access control intermediary services must be configured with a pre-established trust relationship and mechanisms with appropriate authorities (e.g., Active Directory or AAA server) that validate user account access authorizations and privileges.'
  desc 'User account and privilege validation must be centralized in order to prevent unauthorized access using changed or revoked privileges.

ALGs can implement functions such as traffic filtering, authentication, access, and authorization functions based on computer and user privileges. However, the directory service (e.g., Active Directory or LDAP) must not be installed on the ALG, particularly if the Gateway resides on the untrusted zone of the enclave.

The CA API Gateway must have registered identity providers in a central location on the Gateway that provides a pre-established trust for use in authentication and authorization to Registered Services.'
  desc 'check', 'Open the CA API Gateway - Policy Manager.

Select the "Identity Providers" tab and verify all appropriate Identity Providers are listed in accordance with organizational requirements.

If they are not, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager. 

Select the "Identity Providers" tab, right-click "Identity Providers", and register the appropriate Identity Providers to establish the trust on the Gateway in accordance with organizational requirements.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71751r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71351'
  tag rid: 'SV-85975r1_rule'
  tag stig_id: 'CAGW-GW-000310'
  tag gtitle: 'SRG-NET-000138-ALG-000088'
  tag fix_id: 'F-77661r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
