control 'SV-225377' do
  title 'File Explorer shell protocol must run in protected mode.'
  desc 'The shell protocol will  limit the set of folders applications can open when run in protected mode.  Restricting files an application can open to a limited set of folders increases the security of Windows.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

Value Name: PreXPSP2ShellProtocolBehavior

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> File Explorer -> "Turn off shell protocol protected mode" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27076r471473_chk'
  tag severity: 'medium'
  tag gid: 'V-225377'
  tag rid: 'SV-225377r569185_rule'
  tag stig_id: 'WN12-CC-000091'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27064r471474_fix'
  tag 'documentable'
  tag legacy: ['SV-53045', 'V-15683']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
