control 'SV-243178' do
  title 'The network device must generate audit records when successful/unsuccessful logon attempts occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Review the configuration to verify all attempts to access the device via management connection are logged.

If management connection attempts are not logged, this is a finding.'
  desc 'fix', 'Configure the device to log all access attempts to the device to establish a management connection for administrative access.'
  impact 0.5
  ref 'DPMS Target Network WLAN Bridge Mgmt'
  tag check_id: 'C-46453r719987_chk'
  tag severity: 'medium'
  tag gid: 'V-243178'
  tag rid: 'SV-243178r719989_rule'
  tag stig_id: 'WLAN-ND-000900'
  tag gtitle: 'SRG-APP-000503-NDM-000320'
  tag fix_id: 'F-46410r719988_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
