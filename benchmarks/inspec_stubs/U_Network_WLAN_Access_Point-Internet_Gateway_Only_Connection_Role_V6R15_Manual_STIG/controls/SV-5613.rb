control 'SV-5613' do
  title 'The network device must be configured for a maximum number of unsuccessful SSH logon attempts set at 3 before resetting the interface.'
  desc 'An attacker may attempt to connect to the device using SSH by guessing the authentication method and authentication key or shared secret. Setting the authentication retry to 3 or less strengthens against a Brute Force attack.'
  desc 'check', 'Review the configuration and verify the number of unsuccessful SSH logon attempts is set at 3.

If the device is not configured to reset unsuccessful SSH logon attempts at 3, this is a finding.'
  desc 'fix', 'Configure the network device to require a maximum number of unsuccessful SSH logon attempts at 3.'
  impact 0.5
  ref 'DPMS Target Wireless Access Point'
  tag check_id: 'C-3538r8_chk'
  tag severity: 'medium'
  tag gid: 'V-5613'
  tag rid: 'SV-5613r4_rule'
  tag stig_id: 'NET1646'
  tag gtitle: 'SSH login attempts value is greater than 3.'
  tag fix_id: 'F-5524r9_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
