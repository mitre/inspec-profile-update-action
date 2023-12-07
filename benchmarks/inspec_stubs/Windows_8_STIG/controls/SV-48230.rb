control 'SV-48230' do
  title 'File Explorer shell protocol must run in protected mode.'
  desc 'The shell protocol will  limit the set of folders applications can open when run in protected mode.  Restricting files an application can open, to a limited set of folders, increases the security of Windows.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

Value Name: PreXPSP2ShellProtocolBehavior

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> File Explorer -> "Turn off shell protocol protected mode" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44909r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15683'
  tag rid: 'SV-48230r1_rule'
  tag stig_id: 'WN08-CC-000091'
  tag gtitle: 'Windows Explorer – Shell Protocol Protected Mode'
  tag fix_id: 'F-41366r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
