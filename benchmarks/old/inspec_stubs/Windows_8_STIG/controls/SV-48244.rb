control 'SV-48244' do
  title 'Users must be prompted for a password on resume from sleep (on battery).'
  desc 'Authentication must always be required when accessing a system.  This setting ensures the user is prompted for a password on resume from sleep (on battery).'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\\

Value Name: DCSettingIndex

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Power Management -> Sleep Settings -> "Require a password when a computer wakes (on battery)" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44923r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15705'
  tag rid: 'SV-48244r2_rule'
  tag stig_id: 'WN08-CC-000054'
  tag gtitle: 'Power Mgmt – Password Wake on Battery'
  tag fix_id: 'F-41380r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
