control 'SV-71901' do
  title 'The system must be configured to store all data in the error report archive.'
  desc 'The error reporting archive is stored locally on the system and is created after an error report has been sent to the local collector or DOD-wide collector (if defined).  Storing all data, including memory contents, adds data that is very helpful in analyzing the errors.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting\\

Value Name:  ConfigureArchive

Type:  REG_DWORD
Value:  0x00000002 (2)'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> Advanced Error Reporting Settings -> "Configure Report Archive" to "Enabled" with "Store All" selected for "Archive behavior:".'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-58331r1_chk'
  tag severity: 'medium'
  tag gid: 'V-57465'
  tag rid: 'SV-71901r1_rule'
  tag stig_id: 'WINER-000011'
  tag gtitle: 'WINER-000011'
  tag fix_id: 'F-62699r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
