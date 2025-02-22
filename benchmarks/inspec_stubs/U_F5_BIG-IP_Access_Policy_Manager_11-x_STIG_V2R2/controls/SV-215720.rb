control 'SV-215720' do
  title 'The BIG-IP APM module must restrict user authentication traffic to specific authentication server(s) when providing user authentication to virtual servers.'
  desc "User authentication can be used as part of the policy filtering rule sets. Some URLs or network resources can be restricted to authenticated users only. Users are prompted by the application or browser for credentials. Authentication service may be provided by the ALG as an intermediary for the application; however, the authentication credential must be stored in the site's directory services server.

This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., proxy capability). This does not apply to authentication for the purpose of configuring the device itself (i.e., device management)."
  desc 'check', 'If the BIG-IP APM module does not provide user authentication intermediary services, this is not applicable.

Verify the BIG-IP APM module is configured as follows:

Navigate to the BIG-IP System manager >> Access Policy >> Access Profiles.

Click "Edit..." in the "Access Policy" column for an Access Profile used for granting access.

Verify the Access Profile is configured to restrict user authentication traffic to specific authentication server(s).

If the BIG-IP APM module is not configured to restrict user authentication traffic to a specific authentication server(s), this is a finding.'
  desc 'fix', 'If user authentication intermediary services are provided, configure an access policy in the BIG-IP APM module to restrict user authentication traffic to specific authentication server(s).'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Access Policy Manager 11.x'
  tag check_id: 'C-16913r290406_chk'
  tag severity: 'medium'
  tag gid: 'V-215720'
  tag rid: 'SV-215720r557355_rule'
  tag stig_id: 'F5BI-AP-000077'
  tag gtitle: 'SRG-NET-000138-ALG-000089'
  tag fix_id: 'F-16911r290407_fix'
  tag 'documentable'
  tag legacy: ['SV-74461', 'V-60031']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
