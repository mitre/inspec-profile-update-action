control 'SV-14851' do
  title 'User Account Control - Run all admins in Admin Approval Mode'
  desc 'This check verifies that UAC has not been disabled.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “User Account Control: Run all administrators in Admin Approval Mode” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-14240'
  tag rid: 'SV-14851r1_rule'
  tag gtitle: 'UAC - All Admin Approval Mode'
  tag fix_id: 'F-28846r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
