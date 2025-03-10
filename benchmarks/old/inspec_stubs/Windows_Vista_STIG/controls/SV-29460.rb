control 'SV-29460' do
  title 'Media Player – First Use Dialog Boxes'
  desc 'This check verifies that users are not presented with Privacy and Installation options on first use of Windows Media Player.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Media Player “Do Not Show First Use Dialog Boxes” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-15687'
  tag rid: 'SV-29460r1_rule'
  tag gtitle: 'Media Player – First Use Dialog Boxes'
  tag fix_id: 'F-15554r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
