control 'SV-226338' do
  title 'User Account Control approval mode for the built-in Administrator must be enabled.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting configures the built-in Administrator account so that it runs in Admin Approval Mode.

'
  desc 'check', 'UAC requirements are NA on Server Core installations.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: FilterAdministratorToken

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'UAC requirements are NA on Server Core installations.

Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "User Account Control: Admin Approval Mode for the Built-in Administrator account" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-28040r476858_chk'
  tag severity: 'medium'
  tag gid: 'V-226338'
  tag rid: 'SV-226338r794673_rule'
  tag stig_id: 'WN12-SO-000077'
  tag gtitle: 'SRG-OS-000373-GPOS-00157'
  tag fix_id: 'F-28028r476859_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00158']
  tag 'documentable'
  tag legacy: ['SV-52946', 'V-14234']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
