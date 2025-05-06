control 'SV-16640' do
  title 'Device Install – Drivers System Restore Point'
  desc 'This check verifies that a system restore point will be created when a new device driver is installed.'
  desc 'fix', 'Vista - Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation “Do not create a system restore point when new device driver installed” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-15701'
  tag rid: 'SV-16640r1_rule'
  tag gtitle: 'Device Install – Drivers System Restore Point'
  tag fix_id: 'F-15593r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
