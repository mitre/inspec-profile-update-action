control 'SV-220554' do
  title 'The Cisco switch must be configured to authenticate Network Time Protocol (NTP) sources using authentication that is cryptographically based.'
  desc 'If Network Time Protocol is not authenticated, an attacker can introduce a rogue NTP server. This rogue server can then be used to send incorrect time information to network devices, which will make log timestamps inaccurate and affect scheduled actions. NTP authentication is used to prevent this tampering by authenticating the time source.'
  desc 'check', 'Review the Cisco switch configuration to verify that it is compliant with this requirement as shown in the configuration example below:

ntp authentication-key 1 md5 121B0A151012 7
ntp authenticate
ntp trusted-key 1
ntp server x.x.x.x key 1
ntp server y.y.y.y key 1

If the Cisco switch is not configured to authenticate NTP sources using authentication that is cryptographically based, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to authenticate NTP sources using authentication that is cryptographically based as shown in the example below:

SW2(config)#ntp authenticate
SW2(config)#ntp authentication-key 1 md5 xxxxxx
SW2(config)#ntp trusted-key 1
SW2(config)#ntp server x.x.x.x key 1
SW2(config)#ntp server y.y.y.y key 1'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Switch NDM'
  tag check_id: 'C-22269r508606_chk'
  tag severity: 'medium'
  tag gid: 'V-220554'
  tag rid: 'SV-220554r860797_rule'
  tag stig_id: 'CISC-ND-001150'
  tag gtitle: 'SRG-APP-000395-NDM-000347'
  tag fix_id: 'F-22258r508607_fix'
  tag 'documentable'
  tag legacy: ['SV-110563', 'V-101459']
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
