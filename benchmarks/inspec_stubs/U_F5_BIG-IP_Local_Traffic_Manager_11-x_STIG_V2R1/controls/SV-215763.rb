control 'SV-215763' do
  title 'The BIG-IP Core implementation providing PKI-based, user authentication intermediary services must be configured to map the authenticated identity to the user account for PKI-based authentication to virtual servers.'
  desc 'Authorization for access to any network element requires an approved and assigned individual account identifier. To ensure only the assigned individual is using the account, the account must be bound to a user certificate when PKI-based authentication is implemented.

This requirement applies to ALGs that provide user authentication intermediary services (e.g., authentication gateway or TLS gateway). This does not apply to authentication for the purpose of configuring the device itself (device management).'
  desc 'check', 'If the BIG-IP Core does not provide PKI-based, user authentication intermediary services for virtual servers, this is not applicable.

When PKI-based, user authentication intermediary services are provided, verify the BIG-IP LTM module is configured as follows:

Verify Virtual Server(s) in the BIG-IP LTM module are configured with an APM policy to map the authenticated identity to the user account for PKI-based authentication.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Verify under "Access Policy" section, that "Access Policy" has been set to use an APM access policy that maps the authenticated identity to the user account for PKI-based authentication to virtual servers.

If the BIG-IP Core does not map the authenticated identity to the user account for PKI-based authentication, this is a finding.'
  desc 'fix', 'If PKI-based, user authentication intermediary services are provided, configure the BIG-IP Core as follows: 

Configure a policy in the BIG-IP APM module to map the authenticated identity to the user account for PKI-based authentication.

Apply APM policy to the applicable Virtual Server(s) in BIG-IP LTM module to map the authenticated identity to the user account for PKI-based authentication to virtual servers.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16955r291102_chk'
  tag severity: 'medium'
  tag gid: 'V-215763'
  tag rid: 'SV-215763r557356_rule'
  tag stig_id: 'F5BI-LT-000085'
  tag gtitle: 'SRG-NET-000166-ALG-000101'
  tag fix_id: 'F-16953r291103_fix'
  tag 'documentable'
  tag legacy: ['V-60307', 'SV-74737']
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
