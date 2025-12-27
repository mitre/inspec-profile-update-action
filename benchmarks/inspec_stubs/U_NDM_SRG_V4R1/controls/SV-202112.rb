control 'SV-202112' do
  title 'The network device must authenticate Network Time Protocol sources using authentication that is cryptographically based.'
  desc 'If Network Time Protocol is not authenticated, an attacker can introduce a rogue NTP server. This rogue server can then be used to send incorrect time information to network devices, which will make log timestamps inaccurate and affect scheduled actions. NTP authentication is used to prevent this tampering by authenticating the time source.'
  desc 'check', 'Review the network device configuration to determine if the network device authenticates NTP endpoints before establishing a local, remote, or network connection using authentication that is cryptographically based.

If the network device does not authenticate Network Time Protocol sources using authentication that is cryptographically based, this is a finding.'
  desc 'fix', 'Configure the network device to authenticate Network Time Protocol sources using authentication that is cryptographically based.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2238r381956_chk'
  tag severity: 'medium'
  tag gid: 'V-202112'
  tag rid: 'SV-202112r400051_rule'
  tag stig_id: 'SRG-APP-000395-NDM-000347'
  tag gtitle: 'SRG-APP-000395'
  tag fix_id: 'F-2239r381957_fix'
  tag 'documentable'
  tag legacy: ['SV-83339', 'V-68747']
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
