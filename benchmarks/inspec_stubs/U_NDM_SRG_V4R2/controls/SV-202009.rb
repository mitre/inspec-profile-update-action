control 'SV-202009' do
  title 'The network device must retain the session lock until the administrator  reestablishes access using established identification and authentication procedures.'
  desc 'A session lock is a temporary network device or administrator-initiated action taken when the administrator stops work but does not log out of the network device.  Once invoked, the session lock shall remain in place until the administrator re-authenticates. No other system activity aside from re-authentication shall unlock the management session.'
  desc 'check', 'Review the network device configuration to determine if the device retains session lock until the administrator re-authenticates.  This may be verified by configuration check, demonstration, or other validation test results. If the device does not require re-authentication before releasing the session lock, this is a finding.'
  desc 'fix', 'Configure the network device to retain session lock until the administrator re-authenticates.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2135r381566_chk'
  tag severity: 'medium'
  tag gid: 'V-202009'
  tag rid: 'SV-202009r879515_rule'
  tag stig_id: 'SRG-APP-000005-NDM-000204'
  tag gtitle: 'SRG-APP-000005'
  tag fix_id: 'F-2136r381567_fix'
  tag 'documentable'
  tag legacy: ['SV-69281', 'V-55035']
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']
end
