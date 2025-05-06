control 'SV-29230' do
  title 'Solicited Remote Assistance is allowed.'
  desc 'This setting controls whether or not solicited remote assistance is allowed from this computer.  Solicited assistance is help that is specifically requested by the user.  This is a Category 1 finding because it may allow unauthorized parties access to the resources on the computer.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Subkey: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\ 

Value Name: fAllowToGetHelp
 
Type: REG_DWORD 
Value: 0'
  desc 'fix', 'Configure the system to disable Remote Assistance by setting the policy value for Computer Configuration -> Administrative Templates -> System -> Remote Assistance “Solicited Remote Assistance” to “Disabled”.'
  impact 0.7
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-4088r1_chk'
  tag severity: 'high'
  tag gid: 'V-3343'
  tag rid: 'SV-29230r1_rule'
  tag gtitle: 'Remote Assistance - Solicit Remote Assistance'
  tag fix_id: 'F-6777r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
