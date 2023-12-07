control 'SV-225348' do
  title 'Copying of user input methods to the system account for sign-in must be prevented.'
  desc 'Allowing different input methods for sign-in could open different avenues of attack.  User input methods must be restricted to those enabled for the system account at sign-in.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Control Panel\\International\\

Value Name: BlockUserInputMethodsForSignIn

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Locale Services -> "Disallow copying of user input methods to the system account for sign-in" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27047r471386_chk'
  tag severity: 'medium'
  tag gid: 'V-225348'
  tag rid: 'SV-225348r569185_rule'
  tag stig_id: 'WN12-CC-000048'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27035r471387_fix'
  tag 'documentable'
  tag legacy: ['V-36681', 'SV-51610']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
