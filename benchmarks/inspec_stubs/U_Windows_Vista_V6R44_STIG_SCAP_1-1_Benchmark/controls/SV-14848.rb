control 'SV-14848' do
  title 'User Account Control - Detect Application Installations'
  desc 'This check verifies whether Windows responds to application installation requests by prompting for credentials.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “User Account Control: Detect application installations and prompt for elevation” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-14237'
  tag rid: 'SV-14848r1_rule'
  tag gtitle: 'UAC - Application Installations'
  tag fix_id: 'F-28844r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
