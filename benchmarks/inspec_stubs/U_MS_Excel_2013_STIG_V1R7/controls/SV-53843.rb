control 'SV-53843' do
  title 'Corrupt workbook options must be disallowed.'
  desc "This setting controls whether Excel presents users with a list of data extraction options before beginning an Open and Repair operation when users choose to open a corrupt workbook in repair or extract mode. A corrupt Excel file may be indicative of malicious tampering. By allowing the automatic handling of corrupt spreadsheets, malicious code may be introduced to the user's computer and the network."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Data Recovery -> "Do not show data extraction options when opening corrupt workbooks" is set to "Enabled".                                                                                                           Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\microsoft\\office\\15.0\\excel\\options                                                                                                          Criteria: If the value extractdatadisableui is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Data Recovery -> "Do not show data extraction options when opening corrupt workbooks" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2013'
  tag check_id: 'C-47897r1_chk'
  tag severity: 'medium'
  tag gid: 'V-41346'
  tag rid: 'SV-53843r1_rule'
  tag stig_id: 'DTOO419'
  tag gtitle: 'DTOO419 - Disallow corrupt workbook options'
  tag fix_id: 'F-46746r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
