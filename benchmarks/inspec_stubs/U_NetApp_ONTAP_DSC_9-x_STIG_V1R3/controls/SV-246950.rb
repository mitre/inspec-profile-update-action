control 'SV-246950' do
  title 'ONTAP must authenticate NTP sources using authentication that is cryptographically based.'
  desc 'If Network Time Protocol (NTP) is not authenticated, an attacker can introduce a rogue NTP server. This rogue server can then be used to send incorrect time information to network devices, which will make log timestamps inaccurate and affect scheduled actions. NTP authentication is used to prevent this tampering by authenticating the time source.'
  desc 'check', 'Use "cluster time-service ntp server show" to see authenticated NTP sources using authentication that is cryptographically based.

If any of the NTP servers listed has the field "Is Authentication Enabled" set to false, this is a finding.'
  desc 'fix', 'Configure an authenticated NTP source using authentication that is cryptographically based with "cluster time-service ntp server create -server <ip_address> -key-id <NTP_Symmetric_Authentication_Key_ID>".'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50382r860690_chk'
  tag severity: 'medium'
  tag gid: 'V-246950'
  tag rid: 'SV-246950r860691_rule'
  tag stig_id: 'NAOT-IA-000004'
  tag gtitle: 'SRG-APP-000395-NDM-000347'
  tag fix_id: 'F-50336r769181_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
