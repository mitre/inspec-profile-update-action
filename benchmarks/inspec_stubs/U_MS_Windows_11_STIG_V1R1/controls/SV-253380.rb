control 'SV-253380' do
  title 'Users must be prompted for a password on resume from sleep (on battery).'
  desc 'Authentication must always be required when accessing a system. This setting ensures the user is prompted for a password on resume from sleep (on battery).'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\\

Value Name: DCSettingIndex

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Power Management >> Sleep Settings >> "Require a password when a computer wakes (on battery)" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56833r829222_chk'
  tag severity: 'medium'
  tag gid: 'V-253380'
  tag rid: 'SV-253380r829224_rule'
  tag stig_id: 'WN11-CC-000145'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-56783r829223_fix'
  tag 'documentable'
  tag cci: ['CCI-002008']
  tag nist: ['IA-5 (14)']
end
