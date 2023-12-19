control 'SV-32496' do
  title 'Passwords will not be saved in the Remote Desktop Client.'
  desc 'This check verifies that the system is configured to prevent users from saving passwords in the Remote Desktop Client.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:   HKEY_LOCAL_MACHINE
Subkey:   \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name:   DisablePasswordSaving

Type:   REG_DWORD
Value:   1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Connection Client “Do not allow passwords to be saved” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-11593r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14247'
  tag rid: 'SV-32496r1_rule'
  tag gtitle: 'TS/RDS - Prevent Password Saving'
  tag fix_id: 'F-28883r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
