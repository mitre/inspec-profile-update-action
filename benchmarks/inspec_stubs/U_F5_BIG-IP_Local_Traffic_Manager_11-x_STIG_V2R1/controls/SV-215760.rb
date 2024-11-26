control 'SV-215760' do
  title 'The BIG-IP Core implementation providing user authentication intermediary services must restrict user authentication traffic to specific authentication server(s) when providing access control to virtual servers.'
  desc "User authentication can be used as part of the policy filtering rule sets. Some URLs or network resources can be restricted to authenticated users only. Users are prompted by the application or browser for credentials. Authentication service may be provided by the ALG as an intermediary for the application; however, the authentication credential must be stored in the site's directory services server.

This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., proxy capability). This does not apply to authentication for the purpose of configuring the device itself (i.e., device management)."
  desc 'check', 'If the BIG-IP Core does not provide user authentication intermediary services for virtual servers, this is not applicable.

When user authentication intermediary services are provided, verify the BIG-IP Core is configured as follows:

Verify Virtual Server(s) in the BIG-IP LTM module are configured with an APM policy to use a specific authentication server(s).

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Verify under "Access Policy" section that "Access Policy" has been set to use an APM access policy that has been configured with a pre-established trust relationship and mechanisms with appropriate authorities that validate each user access authorization and privileges.

If the BIG-IP Core provides user authentication intermediary services and does not restrict user authentication traffic to a specific authentication server(s), this is a finding.'
  desc 'fix', 'If user authentication intermediary services are provided, configure the BIG-IP Core to use a specific authentication server(s) as follows: 

Configure a policy in the BIG-IP APM module to use authentication for network access to non-privileged accounts.

Apply the APM policy to the applicable Virtual Server(s) in BIG-IP LTM module to restrict user authentication traffic to specific authentication server(s) when providing access control to virtual servers.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16952r291093_chk'
  tag severity: 'medium'
  tag gid: 'V-215760'
  tag rid: 'SV-215760r557356_rule'
  tag stig_id: 'F5BI-LT-000077'
  tag gtitle: 'SRG-NET-000138-ALG-000089'
  tag fix_id: 'F-16950r291094_fix'
  tag 'documentable'
  tag legacy: ['V-60301', 'SV-74731']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
