control 'SV-243167' do
  title 'The network device must authenticate Network Time Protocol (NTP) sources using authentication that is cryptographically based.'
  desc 'If Network Time Protocol is not authenticated, an attacker can introduce a rogue NTP server. This rogue server can then be used to send incorrect time information to network devices, which will make log timestamps inaccurate and affect scheduled actions. NTP authentication is used to prevent this tampering by authenticating the time source.'
  desc 'check', 'Review the network device configuration to determine if the network device authenticates NTP endpoints before establishing a local, remote, or network connection using authentication that is cryptographically based.

If the network device does not authenticate Network Time Protocol sources using authentication that is cryptographically based, this is a finding.'
  desc 'fix', 'Configure the device to authenticate all received NTP messages using a FIPS-approved message authentication code algorithm.'
  impact 0.5
  ref 'DPMS Target Network WLAN AP-NIPR Mgmt'
  tag check_id: 'C-46442r719954_chk'
  tag severity: 'medium'
  tag gid: 'V-243167'
  tag rid: 'SV-243167r879768_rule'
  tag stig_id: 'WLAN-ND-001600'
  tag gtitle: 'SRG-APP-000395-NDM-000347'
  tag fix_id: 'F-46399r719955_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
