control 'SV-32506' do
  title 'The system will be configured to prevent users from redirecting Plug and Play devices to the Remote Desktop Session Host. (Remote Desktop Services Role)'
  desc 'This check verifies that the system is configured to prevent users from redirecting Plug and Play devices to the Remote Desktop Session Host.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name:  fDisablePNPRedir

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Device and Resource Redirection “Do not allow supported Plug and Play device redirection” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32907r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15999'
  tag rid: 'SV-32506r1_rule'
  tag gtitle: 'TS/RDS - PNP Device Redirection'
  tag fix_id: 'F-28926r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
