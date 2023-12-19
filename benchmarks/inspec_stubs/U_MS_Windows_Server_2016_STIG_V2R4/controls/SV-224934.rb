control 'SV-224934' do
  title 'AutoPlay must be disabled for all drives.'
  desc 'Allowing AutoPlay to execute may introduce malicious code to a system. AutoPlay begins reading from a drive as soon media is inserted into the drive. As a result, the setup file of programs or music on audio media may start. By default, AutoPlay is disabled on removable drives, such as the floppy disk drive (but not the CD-ROM drive) and on network drives. Enabling this policy disables AutoPlay on all drives.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\\

Value Name: NoDriveTypeAutoRun

Type: REG_DWORD
Value: 0x000000ff (255)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> AutoPlay Policies >> "Turn off AutoPlay" to "Enabled" with "All Drives" selected.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26625r465704_chk'
  tag severity: 'high'
  tag gid: 'V-224934'
  tag rid: 'SV-224934r569186_rule'
  tag stig_id: 'WN16-CC-000270'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-26613r465705_fix'
  tag 'documentable'
  tag legacy: ['SV-88213', 'V-73549']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
