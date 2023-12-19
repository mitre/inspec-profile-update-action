control 'SV-254488' do
  title 'Windows Server 2022 User Account Control (UAC) must run all administrators in Admin Approval Mode, enabling UAC.'
  desc 'UAC is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting enables UAC.

'
  desc 'check', 'UAC requirements are NA for Server Core installations (this is the default installation option for Windows Server 2022 versus Server with Desktop Experience).

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: EnableLUA

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> User Account Control: Run all administrators in Admin Approval Mode to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57973r849278_chk'
  tag severity: 'medium'
  tag gid: 'V-254488'
  tag rid: 'SV-254488r849280_rule'
  tag stig_id: 'WN22-SO-000440'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-57924r849279_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157']
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
