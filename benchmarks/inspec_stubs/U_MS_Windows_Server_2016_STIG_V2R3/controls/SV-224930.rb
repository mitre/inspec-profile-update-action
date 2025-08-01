control 'SV-224930' do
  title 'Users must be prompted to authenticate when the system wakes from sleep (plugged in).'
  desc 'A system that does not require authentication when resuming from sleep may provide access to unauthorized users. Authentication must always be required when accessing a system. This setting ensures users are prompted for a password when the system wakes from sleep (plugged in).'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\\

Value Name: ACSettingIndex

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Power Management >> Sleep Settings >> "Require a password when a computer wakes (plugged in)" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26621r465692_chk'
  tag severity: 'medium'
  tag gid: 'V-224930'
  tag rid: 'SV-224930r569186_rule'
  tag stig_id: 'WN16-CC-000220'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26609r465693_fix'
  tag 'documentable'
  tag legacy: ['SV-88201', 'V-73539']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
