control 'SV-225354' do
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
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27053r471404_chk'
  tag severity: 'high'
  tag gid: 'V-225354'
  tag rid: 'SV-225354r569185_rule'
  tag stig_id: 'WN12-CC-000059'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-27041r471405_fix'
  tag 'documentable'
  tag legacy: ['SV-52885', 'V-3343']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
