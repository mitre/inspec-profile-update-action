control 'SV-226172' do
  title 'Users must be prompted to authenticate on resume from sleep (on battery).'
  desc 'Authentication must always be required when accessing a system.  This setting ensures the user is prompted for a password on resume from sleep (on battery).'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\\

Value Name: DCSettingIndex

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Power Management -> Sleep Settings -> "Require a password when a computer wakes (on battery)" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27874r475839_chk'
  tag severity: 'medium'
  tag gid: 'V-226172'
  tag rid: 'SV-226172r852097_rule'
  tag stig_id: 'WN12-CC-000054'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-27862r475840_fix'
  tag 'documentable'
  tag legacy: ['SV-53131', 'V-15705']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
