control 'SV-225352' do
  title 'The user must be prompted to authenticate on resume from sleep (plugged in).'
  desc 'Authentication must always be required when accessing a system.  This setting ensures the user is prompted for a password on resume from sleep (plugged in).'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\\

Value Name: ACSettingIndex

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Power Management -> Sleep Settings -> "Require a password when a computer wakes (plugged in)" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27051r471398_chk'
  tag severity: 'medium'
  tag gid: 'V-225352'
  tag rid: 'SV-225352r852207_rule'
  tag stig_id: 'WN12-CC-000055'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-27039r471399_fix'
  tag 'documentable'
  tag legacy: ['SV-53132', 'V-15706']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
