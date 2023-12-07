control 'SV-226175' do
  title 'Solicited Remote Assistance must not be allowed.'
  desc 'Remote assistance allows another user to view or take control of the local session of a user.  Solicited assistance is help that is specifically requested by the local user.  This may allow unauthorized parties access to the resources on the computer.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\ 

Value Name: fAllowToGetHelp
 
Type: REG_DWORD 
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Remote Assistance -> "Configure Solicited Remote Assistance" to "Disabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27877r475848_chk'
  tag severity: 'high'
  tag gid: 'V-226175'
  tag rid: 'SV-226175r794455_rule'
  tag stig_id: 'WN12-CC-000059'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-27865r475849_fix'
  tag 'documentable'
  tag legacy: ['V-3343', 'SV-52885']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
