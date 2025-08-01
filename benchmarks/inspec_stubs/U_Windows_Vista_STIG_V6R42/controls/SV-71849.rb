control 'SV-71849' do
  title 'The system must be configured to prevent the display of error messages to the user.'
  desc 'Displaying error messages to users provides them the option of sending the reports.  Error reports should be sent silently, unknown to the user.  This setting controls whether users are shown an error dialog box that lets them report an error.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting\\

Value Name:  DontShowUI

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> "Prevent display of the user interface for critical errors" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-58281r1_chk'
  tag severity: 'medium'
  tag gid: 'V-57455'
  tag rid: 'SV-71849r1_rule'
  tag stig_id: 'WINER-000006'
  tag gtitle: 'WINER-000006'
  tag fix_id: 'F-62641r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
