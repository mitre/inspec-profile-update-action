control 'SV-16652' do
  title 'Defender – SpyNet Reporting'
  desc 'This check verifies that SpyNet membership is disabled.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender “Configure Microsoft Spynet Reporting” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-15713'
  tag rid: 'SV-16652r1_rule'
  tag gtitle: 'Defender – SpyNet Reporting'
  tag fix_id: 'F-15605r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
