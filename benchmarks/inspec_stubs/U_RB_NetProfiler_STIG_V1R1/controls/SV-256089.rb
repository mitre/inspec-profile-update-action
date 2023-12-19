control 'SV-256089' do
  title 'The Riverbed NetProfiler must be configured to authenticate Network Time Protocol (NTP) sources using authentication that is cryptographically based.'
  desc 'If NTP is not authenticated, an attacker can introduce a rogue NTP server. This rogue server can then be used to send incorrect time information to network devices, which will make log timestamps inaccurate and affect scheduled actions. NTP authentication is used to prevent this tampering by authenticating the time source.'
  desc 'check', 'Go to Administration >> General Settings. 

Under "Time Configuration", verify the "Encryption" for the NTP servers is set to "SHA-1" and the Key and Index columns have a value that corresponds to each NTP server. 

If SHA-1 is not configured for the NTP servers, this is a finding.'
  desc 'fix', 'Go to Administration >> General Settings. 

Under "Time Configuration", change the "Encryption" for the NTP Servers to "SHA-1", and under the Key and Index columns, enter the value that corresponds to each NTP server.'
  impact 0.5
  ref 'DPMS Target Riverbed NetProfiler'
  tag check_id: 'C-59763r882773_chk'
  tag severity: 'medium'
  tag gid: 'V-256089'
  tag rid: 'SV-256089r882775_rule'
  tag stig_id: 'RINP-DM-000052'
  tag gtitle: 'SRG-APP-000395-NDM-000347'
  tag fix_id: 'F-59706r882774_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
