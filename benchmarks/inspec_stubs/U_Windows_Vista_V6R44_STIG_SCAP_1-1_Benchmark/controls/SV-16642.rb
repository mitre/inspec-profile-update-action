control 'SV-16642' do
  title 'Driver Install – Device Driver Search Prompt'
  desc 'This check verifies that users will not be prompted to search Windows Updated for device drivers.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Driver Installation “Turn off Windows Update device driver search prompt” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-15703'
  tag rid: 'SV-16642r1_rule'
  tag gtitle: 'Driver Install – Device Driver Search Prompt'
  tag fix_id: 'F-15595r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
