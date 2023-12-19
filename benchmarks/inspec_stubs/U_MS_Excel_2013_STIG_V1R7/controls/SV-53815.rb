control 'SV-53815' do
  title 'The Update of automatic links setting must be configured to prompt user before allowing links to be updated.'
  desc "If an Excel workbook contains links to other documents and users are not prompted to approve them, the contents of the workbook might change without the users' knowledge because the linked files have changed. This has the risk of introducing corrupt or malicious content into the document. Prompting the user to update links will allow the content to be updated only with the user's knowledge."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Excel options -> Advanced -> "Ask to update automatic links" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\Microsoft\\office\\15.0\\excel\\options\\binaryoptions

Criteria: If the value fupdateext_78_1 is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Excel options -> Advanced -> "Ask to update automatic links" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2013'
  tag check_id: 'C-47886r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17732'
  tag rid: 'SV-53815r1_rule'
  tag stig_id: 'DTOO150'
  tag gtitle: 'DTOO150 - Automatic Link Updates'
  tag fix_id: 'F-46723r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
