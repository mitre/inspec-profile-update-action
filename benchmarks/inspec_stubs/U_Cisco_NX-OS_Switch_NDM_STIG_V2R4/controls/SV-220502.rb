control 'SV-220502' do
  title 'The Cisco switch must be configured to authenticate Network Time Protocol (NTP) sources using authentication that is cryptographically based.'
  desc 'If Network Time Protocol is not authenticated, an attacker can introduce a rogue NTP server. This rogue server can then be used to send incorrect time information to network devices, which will make log timestamps inaccurate and affect scheduled actions. NTP authentication is used to prevent this tampering by authenticating the time source.'
  desc 'check', 'Review the Cisco switch configuration to verify that it is compliant with this requirement as shown in the configuration example below:

ntp distribute
ntp server 10.1.12.10 key 1
ntp server 10.1.22.13 key 1
ntp authenticate
ntp authentication-key 1 md5 xxxxxxxxxx 7
ntp trusted-key 1
ntp commit

If the Cisco switch is not configured to authenticate NTP sources using authentication that is cryptographically based, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to authenticate NTP sources using authentication that is cryptographically based as shown in the example below:

SW1(config)# ntp authenticate
SW1(config)# ntp authentication-key 1 md5 xxxxxxxxxxxxx
SW1(config)# ntp trusted-key 1
SW1(config)# ntp server 10.1.12.10 key 1
SW1(config)# ntp server 10.1.22.13 key 1
SW1(config)# ntp commit
SW1(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch NDM'
  tag check_id: 'C-22217r539227_chk'
  tag severity: 'medium'
  tag gid: 'V-220502'
  tag rid: 'SV-220502r879768_rule'
  tag stig_id: 'CISC-ND-001150'
  tag gtitle: 'SRG-APP-000395-NDM-000347'
  tag fix_id: 'F-22206r539228_fix'
  tag 'documentable'
  tag legacy: ['SV-110653', 'V-101549']
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
