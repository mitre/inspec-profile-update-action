control 'SV-34625' do
  title 'Corrupt workbook options must be disallowed.'
  desc 'This setting controls whether Excel presents users with a list of data extraction options before beginning an Open and Repair operation when users choose to open a corrupt workbook in repair or extract mode.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2010 -> Data Recovery “Do not show data extraction options when opening corrupt workbooks” must be set to “Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\excel\\options

Criteria: If the value ExtractDataDisableUI is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2010 -> Data Recovery “Do not show data extraction options when opening corrupt workbooks” to “Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2010'
  tag check_id: 'C-34190r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26591'
  tag rid: 'SV-34625r1_rule'
  tag stig_id: 'DTOO118 - Excel'
  tag gtitle: 'DTOO118 - Do not show data extraction options'
  tag fix_id: 'F-29883r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
