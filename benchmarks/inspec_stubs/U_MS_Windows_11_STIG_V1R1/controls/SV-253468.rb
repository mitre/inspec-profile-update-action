control 'SV-253468' do
  title 'User Account Control approval mode for the built-in Administrator must be enabled.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. This setting configures the built-in Administrator account so that it runs in Admin Approval Mode.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: FilterAdministratorToken

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "User Account Control: Admin Approval Mode for the Built-in Administrator account" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56921r829486_chk'
  tag severity: 'medium'
  tag gid: 'V-253468'
  tag rid: 'SV-253468r829488_rule'
  tag stig_id: 'WN11-SO-000245'
  tag gtitle: 'SRG-OS-000373-GPOS-00157'
  tag fix_id: 'F-56871r829487_fix'
  tag 'documentable'
  tag cci: ['CCI-002008']
  tag nist: ['IA-5 (14)']
end
