control 'SV-254350' do
  title 'Windows Server 2022 users must be prompted to authenticate when the system wakes from sleep (plugged in).'
  desc 'A system that does not require authentication when resuming from sleep may provide access to unauthorized users. Authentication must always be required when accessing a system. This setting ensures users are prompted for a password when the system wakes from sleep (plugged in).'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\\

Value Name: ACSettingIndex

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Power Management >> Sleep Settings >> Require a password when a computer wakes (plugged in) to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57835r848864_chk'
  tag severity: 'medium'
  tag gid: 'V-254350'
  tag rid: 'SV-254350r848866_rule'
  tag stig_id: 'WN22-CC-000190'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-57786r848865_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
