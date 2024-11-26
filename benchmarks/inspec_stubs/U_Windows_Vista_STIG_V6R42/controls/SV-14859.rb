control 'SV-14859' do
  title 'Users must be prevented from connecting using Terminal Services.'
  desc 'Allowing a Terminal Services session to a workstation enables another avenue of access that could be exploited.  The system must be configured to prevent users from connecting to a computer using Terminal Services.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name:  fDenyTSConnections

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Terminal Services -> Terminal Server -> Connections "Allow users to connect remotely using Terminal Services" to "Disabled.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-51785r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14248'
  tag rid: 'SV-14859r2_rule'
  tag gtitle: 'TS/RDS - Remote User Connections'
  tag fix_id: 'F-53567r1_fix'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
