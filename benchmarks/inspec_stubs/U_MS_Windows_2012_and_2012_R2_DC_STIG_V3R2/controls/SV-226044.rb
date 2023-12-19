control 'SV-226044' do
  title 'System-related documentation must be backed up in accordance with local recovery time and recovery point objectives.'
  desc 'Operating system backup is a critical step in maintaining data assurance and availability. 

Information system and security-related documentation contains information pertaining to system configuration and security settings. 

Backups shall be consistent with organizational recovery time and recovery point objectives.'
  desc 'check', 'Determine whether system-related documentation is backed up in accordance with local recovery time and recovery point objectives.  If system-related documentation is not backed up in accordance with local recovery time and recovery point objectives, this is a finding.'
  desc 'fix', 'Back up system-related documentation in accordance with local recovery time and recovery point objectives.'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27746r475455_chk'
  tag severity: 'low'
  tag gid: 'V-226044'
  tag rid: 'SV-226044r569184_rule'
  tag stig_id: 'WN12-00-000017'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag fix_id: 'F-27734r475456_fix'
  tag 'documentable'
  tag legacy: ['V-40173', 'SV-52131']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
