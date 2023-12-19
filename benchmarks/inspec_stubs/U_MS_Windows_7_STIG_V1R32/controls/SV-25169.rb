control 'SV-25169' do
  title 'The system must be configured to prevent unsolicited remote assistance offers.'
  desc 'Remote assistance allows another user to view or take control of the local session of a user.  Unsolicited remote assistance is help that is offered by the remote user.  This may allow unauthorized parties access to the resources on the computer.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name:  fAllowUnsolicited

Value Type:  REG_DWORD
Value:  0

Offer remote assistance may be enabled on workstations if mitigations are in place.  This must be documented with the ISSO.'
  desc 'fix', 'Configure the system to prevent unsolicited remote assistance offers by setting the policy value for Computer Configuration >> Administrative Templates >> System >> Remote Assistance >> "Offer Remote Assistance" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-62077r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3470'
  tag rid: 'SV-25169r2_rule'
  tag gtitle: 'Remote Assistance - Offer Remote Assistance'
  tag fix_id: 'F-66975r1_fix'
  tag 'documentable'
  tag mitigations: '3.082 Win 7'
  tag third_party_tools: 'HK'
  tag mitigation_control: '-Users must be trained to include the following:
-Users must know who they can accept a remote assistance offer from. The remote assistance offer must be in response to a help desk request or confirmed with the help desk if an unsolicited remote assistance offer comes through.
-Users must know how to accept a request, allow view or control, and disconnect a remote assistance session.
-Users must monitor the remote assistance activity at the workstation while it is occurring.

-The support personnel allowed to offer remote assistance (helpers) must be limited and documented.

-Port 3389 must be blocked at the perimeter to prevent other access.

Accounts and groups authorized to offer remote assistance (helpers) are identified in the following registry key.

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\ RAUnsolicit\\

Each account or group will be listed under a separate value name with the value equaling the value name as in the following examples:

Value Name:  Administrators
Value Type:  REG_SZ
Value:  Administrators

Value Name:  TestUser
Value Type:  REG_SZ
Value:  TestUser'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
