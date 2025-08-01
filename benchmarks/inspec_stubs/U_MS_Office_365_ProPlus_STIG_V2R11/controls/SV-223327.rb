control 'SV-223327' do
  title 'Extraction options must be blocked when opening corrupt Excel workbooks.'
  desc 'This policy setting controls whether Excel presents users with a list of data extraction options before beginning an Open and Repair operation when users choose to open a corrupt workbook in repair or extract mode.

If you enable this policy setting, Excel opens the file using the Safe Load process and does not prompt users to choose between repairing or extracting data.

If you disable or do not configure this policy setting, Excel prompts the user to select either to repair or to extract data, and to select either to convert to values or to recover formulas.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Data Recovery >> Do not show data extraction options when opening corrupt workbooks is set to "Enabled".

Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\microsoft\\office\\16.0\\excel\\options

If the value for extractdatadisableui is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Data Recovery >> Do not show data extraction options when opening corrupt workbooks to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25000r442200_chk'
  tag severity: 'medium'
  tag gid: 'V-223327'
  tag rid: 'SV-223327r879628_rule'
  tag stig_id: 'O365-EX-000018'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-24988r442201_fix'
  tag 'documentable'
  tag legacy: ['SV-108833', 'V-99729']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
