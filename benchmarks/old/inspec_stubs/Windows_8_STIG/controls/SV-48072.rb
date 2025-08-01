control 'SV-48072' do
  title 'Solicited Remote Assistance must not be allowed.'
  desc 'Remote assistance allows another user to view or take control of the local session of a user.  Solicited assistance is help that is specifically requested by the local user.  This may allow unauthorized parties access to the resources on the computer.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Subkey: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\ 

Value Name: fAllowToGetHelp
 
Type: REG_DWORD 
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Remote Assistance -> "Configure Solicited Remote Assistance" to "Disabled".'
  impact 0.7
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44811r1_chk'
  tag severity: 'high'
  tag gid: 'V-3343'
  tag rid: 'SV-48072r1_rule'
  tag stig_id: 'WN08-CC-000059'
  tag gtitle: 'Remote Assistance - Solicit Remote Assistance'
  tag fix_id: 'F-41210r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
