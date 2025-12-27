control 'SV-14845' do
  title 'User Account Control - Built In Admin Approval Mode'
  desc 'This check verifies whether the built-in Administrator account runs in Admin Approval Mode.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “User Account Control: Admin Approval Mode for the Built-in Administrator account” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-14234'
  tag rid: 'SV-14845r1_rule'
  tag gtitle: 'UAC - Admin Approval Mode'
  tag fix_id: 'F-28841r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
