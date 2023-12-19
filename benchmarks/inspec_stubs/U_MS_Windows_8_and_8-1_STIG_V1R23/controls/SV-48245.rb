control 'SV-48245' do
  title 'The user must be prompted for a password on resume from sleep (plugged in).'
  desc 'Authentication must always be required when accessing a system.  This setting ensures the user is prompted for a password on resume from sleep (plugged in).'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\\

Value Name: ACSettingIndex

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Power Management -> Sleep Settings -> "Require a password when a computer wakes (plugged in)" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44924r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15706'
  tag rid: 'SV-48245r2_rule'
  tag stig_id: 'WN08-CC-000055'
  tag gtitle: 'Power Mgmt – Password Wake When Plugged In'
  tag fix_id: 'F-41381r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
