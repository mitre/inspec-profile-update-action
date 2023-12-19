control 'SV-48303' do
  title 'Connected users on domain-joined computers must not be enumerated.'
  desc 'The username is one part of logon credentials that could be used to gain access to a system.  Preventing the enumeration of users limits this information to unauthorized personnel.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\System\\

Value Name: DontEnumerateConnectedUsers

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Logon -> "Do not enumerate connected users on domain-joined computers" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44980r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36683'
  tag rid: 'SV-48303r2_rule'
  tag stig_id: 'WN08-CC-000050'
  tag gtitle: 'WN08-CC-000050'
  tag fix_id: 'F-41437r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
