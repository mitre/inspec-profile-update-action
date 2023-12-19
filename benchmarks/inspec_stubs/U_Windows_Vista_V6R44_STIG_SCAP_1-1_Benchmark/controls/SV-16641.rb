control 'SV-16641' do
  title 'Device Install – Generic Driver Error Report'
  desc 'This check verifies that an Error Report will not be sent when a generic device driver is installed.'
  desc 'fix', 'Vista - Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation “Do not send a Windows Error Report when a generic driver is installed on a system” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-15702'
  tag rid: 'SV-16641r1_rule'
  tag gtitle: 'Device Install – Generic Driver Error Report'
  tag fix_id: 'F-15594r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
