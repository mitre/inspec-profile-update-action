control 'SV-48301' do
  title 'Copying of user input methods to the system account for sign-in must be prevented.'
  desc 'Allowing different input methods for sign-in could open different avenues of attack.  User input methods must be restricted to those enabled for the system account at sign-in.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Control Panel\\International\\

Value Name: BlockUserInputMethodsForSignIn

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Locale Services -> "Disallow copying of user input methods to the system account for sign-in" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44979r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36681'
  tag rid: 'SV-48301r2_rule'
  tag stig_id: 'WN08-CC-000048'
  tag gtitle: 'WINCC-000048'
  tag fix_id: 'F-41436r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
