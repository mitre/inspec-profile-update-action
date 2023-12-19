control 'SV-225061' do
  title 'User Account Control approval mode for the built-in Administrator must be enabled.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting configures the built-in Administrator account so that it runs in Admin Approval Mode.

'
  desc 'check', 'UAC requirements are NA for Server Core installations (this is the default installation option for Windows Server 2016 versus Server with Desktop Experience) as well as Nano Server.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: FilterAdministratorToken

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "User Account Control: Admin Approval Mode for the Built-in Administrator account" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26752r466085_chk'
  tag severity: 'medium'
  tag gid: 'V-225061'
  tag rid: 'SV-225061r852388_rule'
  tag stig_id: 'WN16-SO-000460'
  tag gtitle: 'SRG-OS-000373-GPOS-00157'
  tag fix_id: 'F-26740r466086_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00156']
  tag 'documentable'
  tag legacy: ['SV-88371', 'V-73707']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
