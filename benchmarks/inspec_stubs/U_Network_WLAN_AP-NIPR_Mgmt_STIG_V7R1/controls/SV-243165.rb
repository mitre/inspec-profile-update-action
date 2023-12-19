control 'SV-243165' do
  title 'The network device must be configured to enforce the limit of three consecutive invalid logon attempts, after which time it must block any login attempt for 15 minutes.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced.'
  desc 'check', 'Review the configuration and verify the number of unsuccessful SSH logon attempts is set at "3", after which time it must block any login attempt for 15 minutes.

If the device is not configured to reset unsuccessful SSH logon attempts at "3" and then block any login attempt for 15 minutes, this is a finding.'
  desc 'fix', 'Configure the network device to require a maximum number of unsuccessful SSH logon attempts at "3", after which time it must block any login attempt for 15 minutes.'
  impact 0.5
  ref 'DPMS Target Network WLAN AP-NIPR Mgmt'
  tag check_id: 'C-46440r719948_chk'
  tag severity: 'medium'
  tag gid: 'V-243165'
  tag rid: 'SV-243165r719950_rule'
  tag stig_id: 'WLAN-ND-001400'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-46397r719949_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
