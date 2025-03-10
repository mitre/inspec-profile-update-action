control 'SV-68757' do
  title 'The ALG providing user authentication intermediary services must restrict user authentication traffic to specific authentication server(s).'
  desc "User authentication can be used as part of the policy filtering rule sets. Some URLs or network resources can be restricted to authenticated users only. Users are prompted by the application or browser for credentials. Authentication service may be provided by the ALG as an intermediary for the application; however, the authentication credential must be stored in the site's directory services server.

This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., proxy capability). This does not apply to authentication for the purpose of configuring the device itself (i.e., device management)."
  desc 'check', 'If the ALG does not provide user authentication intermediary services, this is not applicable.

Verify the ALG is configured to use a specific authentication server(s).

If the ALG does not restrict user authentication traffic to a specific authentication server(s), this is a finding.'
  desc 'fix', 'If user authentication intermediary services are provided, configure the ALG to use a specific authentication server(s).'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55127r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54511'
  tag rid: 'SV-68757r1_rule'
  tag stig_id: 'SRG-NET-000138-ALG-000089'
  tag gtitle: 'SRG-NET-000138-ALG-000089'
  tag fix_id: 'F-59365r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
