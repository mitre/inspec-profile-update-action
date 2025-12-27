control 'SV-85661' do
  title 'Corrupt workbook options must be disallowed.'
  desc 'This policy setting controls whether Excel presents users with a list of data extraction options before beginning an Open and Repair operation when users choose to open a corrupt workbook in repair or extract mode. If you enable this policy setting, Excel opens the file using the Safe Load process and does not prompt users to choose between repairing or extracting data. If you disable or do not configure this policy setting, Excel prompts the user to select either to repair or to extract data, and to select either to convert to values or to recover formulas.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2016 -> Data Recovery -> "Do not show data extraction options when opening corrupt workbooks" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\Microsoft\\office\\16.0\\excel\\options 

Criteria: If the value extractdatadisableui is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2016 -> Data Recovery -> "Do not show data extraction options when opening corrupt workbooks" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2016'
  tag check_id: 'C-71465r2_chk'
  tag severity: 'medium'
  tag gid: 'V-71037'
  tag rid: 'SV-85661r1_rule'
  tag stig_id: 'DTOO419'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-77369r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
