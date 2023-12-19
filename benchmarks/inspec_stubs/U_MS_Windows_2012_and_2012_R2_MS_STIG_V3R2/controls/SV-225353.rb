control 'SV-225353' do
  title 'The system must be configured to prevent unsolicited remote assistance offers.'
  desc 'Remote assistance allows another user to view or take control of the local session of a user.  Unsolicited remote assistance is help that is offered by the remote user.  This may allow unauthorized parties access to the resources on the computer.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: fAllowUnsolicited

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Remote Assistance -> "Configure Offer Remote Assistance" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27052r471401_chk'
  tag severity: 'medium'
  tag gid: 'V-225353'
  tag rid: 'SV-225353r569185_rule'
  tag stig_id: 'WN12-CC-000058'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-27040r471402_fix'
  tag 'documentable'
  tag legacy: ['V-3470', 'SV-52917']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
