control 'SV-29456' do
  title 'Windows Installer – User Control'
  desc 'This check verifies that users are prevented from changing installation options.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer “Enable user control over installs” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-15685'
  tag rid: 'SV-29456r1_rule'
  tag gtitle: 'Windows Installer – User Control'
  tag fix_id: 'F-15552r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
