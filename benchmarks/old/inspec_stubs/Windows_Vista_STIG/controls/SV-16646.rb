control 'SV-16646' do
  title 'Remote Assistance – Session Logging'
  desc 'This check verifies that Remote Assistance log files will be generated.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Remote Assistance “Turn on session logging” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-15707'
  tag rid: 'SV-16646r1_rule'
  tag gtitle: 'Remote Assistance – Session Logging'
  tag fix_id: 'F-15599r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
