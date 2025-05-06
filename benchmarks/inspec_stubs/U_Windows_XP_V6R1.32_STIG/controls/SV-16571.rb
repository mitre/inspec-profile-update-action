control 'SV-16571' do
  title 'Terminal Services - Prevent password saving in the Remote Desktop Client'
  desc 'This check verifies that the system is configured to prevent Users from saving passwords in the Remote Desktop Client.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:   HKEY_LOCAL_MACHINE
Subkey:   \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name:   DisablePasswordSaving

Type:   REG_DWORD
Value:   1'
  desc 'fix', 'XP - Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Terminal Services-> Client “Do not allow passwords to be saved” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-11593r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14247'
  tag rid: 'SV-16571r1_rule'
  tag gtitle: 'TS/RDS - Prevent Password Saving'
  tag fix_id: 'F-15528r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
