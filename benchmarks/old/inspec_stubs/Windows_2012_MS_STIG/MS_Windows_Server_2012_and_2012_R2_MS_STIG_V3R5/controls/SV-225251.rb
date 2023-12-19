control 'SV-225251' do
  title 'System-level information must be backed up in accordance with local recovery time and recovery point objectives.'
  desc 'Operating system backup is a critical step in maintaining data assurance and availability. 

System-level information includes system-state information, operating system and application software, and licenses. 

Backups must be consistent with organizational recovery time and recovery point objectives.'
  desc 'check', 'Determine whether system-level information is backed up in accordance with local recovery time and recovery point objectives.  If system-level information is not backed up in accordance with local recovery time and recovery point objectives, this is a finding.'
  desc 'fix', 'Implement system-level information backups in accordance with local recovery time and recovery point objectives.'
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-26950r471095_chk'
  tag severity: 'low'
  tag gid: 'V-225251'
  tag rid: 'SV-225251r569185_rule'
  tag stig_id: 'WN12-00-000014'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26938r471096_fix'
  tag 'documentable'
  tag legacy: ['SV-52841', 'V-1076']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
