control 'SV-14852' do
  title 'User Account Control - Switch to secure desktop'
  desc 'This check verifies that the elevation prompt is only used in secure desktop mode.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “User Account Control: Switch to the secure desktop when prompting for elevation” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-14241'
  tag rid: 'SV-14852r1_rule'
  tag gtitle: 'UAC - Secure Desktop Mode'
  tag fix_id: 'F-28847r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
