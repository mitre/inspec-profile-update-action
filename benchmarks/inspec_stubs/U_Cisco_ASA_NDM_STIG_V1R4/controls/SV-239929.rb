control 'SV-239929' do
  title 'The Cisco ASA must be configured to authenticate Network Time Protocol sources using authentication that is cryptographically based.'
  desc 'If Network Time Protocol is not authenticated, an attacker can introduce a rogue NTP server. This rogue server can then be used to send incorrect time information to network devices, which will make log timestamps inaccurate and affect scheduled actions. NTP authentication is used to prevent this tampering by authenticating the time source.'
  desc 'check', 'Review the Cisco ASA configuration to verify that it is compliant with this requirement as shown in the configuration example below.

ntp authentication-key 1 md5 *****
ntp authenticate
ntp trusted-key 1
ntp server 10.1.12.2 key 1 prefer
ntp server 10.1.48.10 key 1

Note: For ASAs running on Firepower Chassis hardware, the NTP settings are visible in the FXOS web UI only (not in the ASA CLI or ASDM web UI).

If the Cisco ASA is not configured to authenticate NTP sources using authentication that is cryptographically based, this is a finding.'
  desc 'fix', 'Configure the Cisco ASA to authenticate NTP sources using authentication that is cryptographically based as shown in the example below.

ASA(config)# ntp authenticate 
ASA(config)# ntp authentication-key 1 md5 xxxxxxxxxx
ASA(config)# ntp trusted-key 1
ASA(config)# ntp server 10.1.12.2 key 1 prefer
ASA(config)# ntp server 10.1.48.10 key 1
ASA(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43162r666148_chk'
  tag severity: 'medium'
  tag gid: 'V-239929'
  tag rid: 'SV-239929r879768_rule'
  tag stig_id: 'CASA-ND-001080'
  tag gtitle: 'SRG-APP-000395-NDM-000347'
  tag fix_id: 'F-43121r666149_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
