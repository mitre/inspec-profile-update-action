control 'SV-32428' do
  title 'The user will be prompted for a password on resume from sleep (Plugged In).  (Applicable on Server 2008 R2 if the system is configured to sleep.)'
  desc 'This check verifies that the user is prompted for a password on resume from sleep (Plugged In).'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE 
Subkey: \\Software\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\\ 

Value Name: ACSettingIndex 

Type: REG_DWORD 
Value: 1 

Applicable on Server 2008 R2 if the system is configured to sleep.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Power Management -> Sleep Settings “Require a Password When a Computer Wakes (Plugged In)” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32779r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15706'
  tag rid: 'SV-32428r1_rule'
  tag gtitle: 'Power Mgmt – Password Wake When Plugged In'
  tag fix_id: 'F-15598r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
