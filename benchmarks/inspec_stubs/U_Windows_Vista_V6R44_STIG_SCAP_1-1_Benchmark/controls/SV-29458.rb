control 'SV-29458' do
  title 'Windows Installer – Vendor Signed Updates'
  desc 'This check verifies that users are prevented applying vendor signed updates.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer “Prohibit non-administrators from applying vendor signed updates” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-15686'
  tag rid: 'SV-29458r1_rule'
  tag gtitle: 'Windows Installer – Vendor Signed Updates'
  tag fix_id: 'F-15553r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
