control 'SV-70675' do
  title 'The touch keyboard or input panel must not highlight keys as passwords are entered.'
  desc 'The touch keyboard or input panel may highlight keys as passwords are entered, providing visibility to nearby persons, and compromising them.'
  desc 'check', 'If the system does not have a touch screen, this is NA.
If the system has a touch screen and the following registry values do not exist or are not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry path:  \\SOFTWARE\\Policies\\Microsoft\\TabletTip\\1.7\\

Value Name:  PasswordSecurityState
Type:  REG_DWORD
Value:  1

Value Name:  PasswordSecurity
Type:  REG_DWORD
Value:  4 or 5 
(1, 2, or 3 are a finding)'
  desc 'fix', 'If the system does not have a touch screen, this is NA.
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Tablet PC -> Input Panel -> "Turn off password security in Input Panel" to at least "Enabled: Medium High".'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-56975r1_chk'
  tag severity: 'low'
  tag gid: 'V-56421'
  tag rid: 'SV-70675r1_rule'
  tag stig_id: 'WINCC-000147'
  tag gtitle: 'WINCC-000147'
  tag fix_id: 'F-61301r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']
end
