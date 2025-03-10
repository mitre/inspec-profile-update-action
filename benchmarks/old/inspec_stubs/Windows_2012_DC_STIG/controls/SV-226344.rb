control 'SV-226344' do
  title 'User Account Control must run all administrators in Admin Approval Mode, enabling UAC.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting enables UAC.

'
  desc 'check', 'UAC requirements are NA on Server Core installations.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: EnableLUA

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'UAC requirements are NA on Server Core installations.

Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "User Account Control: Run all administrators in Admin Approval Mode" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-28046r476876_chk'
  tag severity: 'medium'
  tag gid: 'V-226344'
  tag rid: 'SV-226344r852152_rule'
  tag stig_id: 'WN12-SO-000083'
  tag gtitle: 'SRG-OS-000373-GPOS-00157'
  tag fix_id: 'F-28034r476877_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00158']
  tag 'documentable'
  tag legacy: ['SV-52951', 'V-14240']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
