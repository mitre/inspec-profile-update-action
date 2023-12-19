control 'SV-254482' do
  title 'Windows Server 2022 User Account Control (UAC) approval mode for the built-in Administrator must be enabled.'
  desc 'UAC is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting configures the built-in Administrator account so that it runs in Admin Approval Mode.

'
  desc 'check', 'UAC requirements are NA for Server Core installations (this is the default installation option for Windows Server 2022 versus Server with Desktop Experience).

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: FilterAdministratorToken

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> User Account Control: Admin Approval Mode for the Built-in Administrator account to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57967r849260_chk'
  tag severity: 'medium'
  tag gid: 'V-254482'
  tag rid: 'SV-254482r849262_rule'
  tag stig_id: 'WN22-SO-000380'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-57918r849261_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157']
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
