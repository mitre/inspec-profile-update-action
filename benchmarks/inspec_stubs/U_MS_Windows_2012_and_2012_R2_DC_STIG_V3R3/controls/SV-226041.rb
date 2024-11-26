control 'SV-226041' do
  title 'System-level information must be backed up in accordance with local recovery time and recovery point objectives.'
  desc 'Operating system backup is a critical step in maintaining data assurance and availability. 

System-level information includes system-state information, operating system and application software, and licenses. 

Backups must be consistent with organizational recovery time and recovery point objectives.'
  desc 'check', 'Determine whether system-level information is backed up in accordance with local recovery time and recovery point objectives.  If system-level information is not backed up in accordance with local recovery time and recovery point objectives, this is a finding.'
  desc 'fix', 'Implement system-level information backups in accordance with local recovery time and recovery point objectives.'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27743r475446_chk'
  tag severity: 'low'
  tag gid: 'V-226041'
  tag rid: 'SV-226041r794378_rule'
  tag stig_id: 'WN12-00-000014'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27731r475447_fix'
  tag 'documentable'
  tag legacy: ['SV-52841', 'V-1076']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
