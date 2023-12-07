control 'SV-29417' do
  title 'Windows Messenger prevented from collecting anonymous information.'
  desc 'This check verifies that the system is configured to prevent Windows Messenger from collecting anonymous information about how the Windows Messenger software and service is used.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication setting ‘Turn off the Windows Messenger Customer Experience Improvement Program’ to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-14257'
  tag rid: 'SV-29417r1_rule'
  tag gtitle: 'Windows Messenger Experience Improvement'
  tag fix_id: 'F-13582r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
