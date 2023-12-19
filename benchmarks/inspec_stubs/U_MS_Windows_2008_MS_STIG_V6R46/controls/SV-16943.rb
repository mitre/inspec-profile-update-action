control 'SV-16943' do
  title 'Terminal Services – Prevent Plug and Play Device Redirection (Terminal Server Role).'
  desc 'This check verifies that the system is configured to prevent users from redirecting Plug and Play devices to the Terminal Services session.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name:  fDisablePNPRedir

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Terminal Services -> Terminal Server -> Device and Resource Redirection “Do not allow supported Plug and Play device redirection” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-32907r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15999'
  tag rid: 'SV-16943r1_rule'
  tag gtitle: 'TS/RDS - PNP Device Redirection'
  tag fix_id: 'F-16014r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
