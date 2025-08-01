control 'SV-29453' do
  title 'Windows Explorer – Shell Protocol Protected Mode'
  desc 'This check verifies that the shell protocol is run in protected mode.  (This allows applications to only open limited folders.)'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

Value Name:  PreXPSP2ShellProtocolBehavior

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Explorer “Turn off shell protocol protected mode” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-15327r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15683'
  tag rid: 'SV-29453r1_rule'
  tag gtitle: 'Windows Explorer – Shell Protocol Protected Mode'
  tag fix_id: 'F-15550r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
