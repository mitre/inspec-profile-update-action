control 'SV-85983' do
  title 'The CA API Gateway providing PKI-based user authentication intermediary services must map authenticated identities to the user account.'
  desc 'Authorization for access to any network element requires an approved and assigned individual account identifier. To ensure only the assigned individual is using the account, the account must be bound to a user certificate when PKI-based authentication is implemented.

This requirement applies to ALGs that provide user authentication intermediary services (e.g., authentication gateway or TLS gateway). This does not apply to authentication for the purpose of configuring the device itself (device management).

When a user is authenticated using PKI, the CA API Gateway must map attributes associated with their certificate in order to query an identity provider mapping the PKI certificate to a user account.'
  desc 'check', %q(Open the CA API Gateway - Policy Manager and double-click the Registered Services requiring certificate mapping to user accounts. 

Verify that the "Require SSL/TLS with Client Certificate Authentication" Assertion is present, that "Extract Attributes from Certificate" is present, and that one of the "Authenticate Against..." Assertions is also present. 

In addition, verify the logic necessary to provide access to the Registered Service's resources is properly enabled using the required policy logic after extracting the proper attributes from the certificate using the "Extract Attributes from Certificate" Assertion. 

If these requirements have not been met within the policy, this is a finding.)
  desc 'fix', %q(Open the CA API Gateway - Policy Manager and double-click the Registered Services requiring certificate mapping to user accounts. 

Update the policy with the "Require SSL/TLS with Client Certificate Authentication", the "Extract Attributes from Certificate", and one of the "Authenticate Against..." Assertions. In addition, create the policy logic necessary to provide access to the Registered Service's resources after extracting the proper attributes from the certificate using the "Extract Attributes from Certificate" Assertion in accordance with organizational requirements.)
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71759r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71359'
  tag rid: 'SV-85983r1_rule'
  tag stig_id: 'CAGW-GW-000350'
  tag gtitle: 'SRG-NET-000166-ALG-000101'
  tag fix_id: 'F-77669r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
