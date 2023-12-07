control 'SV-48325' do
  title 'The password reveal button must not be displayed.'
  desc 'Visible passwords may be seen by nearby persons, compromising them.   The password reveal button can be used to display an entered password and must not be allowed.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\CredUI\\

Value Name: DisablePasswordReveal

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Credential User Interface -> "Do not display the password reveal button" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44996r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36700'
  tag rid: 'SV-48325r2_rule'
  tag stig_id: 'WN08-CC-000076'
  tag gtitle: 'WINCC-000076'
  tag fix_id: 'F-41457r1_fix'
  tag 'documentable'
  tag ia_controls: 'IAIA-1'
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']
end
