control 'SV-225368' do
  title 'The password reveal button must not be displayed.'
  desc 'Visible passwords may be seen by nearby persons, compromising them.  The password reveal button can be used to display an entered password and must not be allowed.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\CredUI\\

Value Name: DisablePasswordReveal

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Credential User Interface -> "Do not display the password reveal button" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27067r471446_chk'
  tag severity: 'medium'
  tag gid: 'V-225368'
  tag rid: 'SV-225368r569185_rule'
  tag stig_id: 'WN12-CC-000076'
  tag gtitle: 'SRG-OS-000079-GPOS-00047'
  tag fix_id: 'F-27055r471447_fix'
  tag 'documentable'
  tag legacy: ['V-36700', 'SV-51740']
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']
end
