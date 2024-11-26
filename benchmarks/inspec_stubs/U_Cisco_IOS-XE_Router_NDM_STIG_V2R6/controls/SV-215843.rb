control 'SV-215843' do
  title 'The Cisco router must be configured to authenticate Network Time Protocol (NTP) sources using authentication that is cryptographically based.'
  desc 'If Network Time Protocol is not authenticated, an attacker can introduce a rogue NTP server. This rogue server can then be used to send incorrect time information to network devices, which will make log timestamps inaccurate and affect scheduled actions. NTP authentication is used to prevent this tampering by authenticating the time source.'
  desc 'check', 'Review the Cisco router configuration to verify that it is compliant with this requirement as shown in the configuration example below.

ntp authentication-key 1 md5 121B0A151012 7
ntp authenticate
ntp trusted-key 1
ntp server x.x.x.x key 1
ntp server y.y.y.y key 1

If the Cisco router is not configured to authenticate NTP sources using authentication that is cryptographically based, this is a finding.'
  desc 'fix', 'Configure the Cisco router to authenticate NTP sources using authentication that is cryptographically based as shown in the example below.

R2(config)#ntp authenticate
R2(config)#ntp authentication-key 1 md5 xxxxxx
R2(config)#ntp trusted-key 1
R2(config)#ntp server x.x.x.x key 1
R2(config)#ntp server y.y.y.y key 1'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router NDM'
  tag check_id: 'C-17082r287568_chk'
  tag severity: 'medium'
  tag gid: 'V-215843'
  tag rid: 'SV-215843r879768_rule'
  tag stig_id: 'CISC-ND-001150'
  tag gtitle: 'SRG-APP-000395-NDM-000347'
  tag fix_id: 'F-17080r287569_fix'
  tag 'documentable'
  tag legacy: ['SV-105459', 'V-96321']
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
