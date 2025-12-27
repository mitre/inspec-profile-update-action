control 'SV-86087' do
  title 'The CA API Gateway providing user authentication intermediary services must transmit only encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

This requirement applies to ALGs that provide user authentication intermediary services. This does not apply to authentication for the purpose of configuring the device itself (device management).

The CA API Gateway must require SSL or TLS when accessing a Registered Service. By requiring SSL or TLS to access a Registered Service, passwords will be encrypted by the CA API Gateway even if the back-end server does not require passwords to be encrypted or have SSL enabled.'
  desc 'check', 'Open the CA API Gateway - Policy Manager and open each of the Registered Services that requires the authentication passwords to be protected.

Verify the "Require SSL or TLS Transport" Assertion is present. 

If it is not, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager and open each of the Registered Services that requires authentication passwords to be protected and that does not include the "Require SSL or TLS Transport" Assertion.

Add the "Require SSL or TLS Transport" Assertion and click the "Save and Activate" button to activate the changes to the policy.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71853r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71463'
  tag rid: 'SV-86087r1_rule'
  tag stig_id: 'CAGW-GW-000830'
  tag gtitle: 'SRG-NET-000400-ALG-000097'
  tag fix_id: 'F-77783r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
