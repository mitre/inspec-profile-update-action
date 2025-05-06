control 'SV-33463' do
  title 'Inclusion of document properties for PDF and XPS output must be disallowed.'
  desc 'If the Microsoft Save as PDF or XPS Add-in for Microsoft Office Programs add-in is installed, document properties are saved as metadata when users save files using the PDF or XPS or Publish as PDF or XPS commands in Access 2010, Excel 2010, InfoPath 2010, PowerPoint 2010, and Word 2010, unless the Document properties option is unchecked in the Options dialog box. If this metadata contains sensitive information, saving it with the file could compromise security.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Microsoft Save As PDF and XPS add-ins “Disable inclusion of document properties in PDF and XPS output” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\fixedformat

Criteria: If the value DisableFixedFormatDocProperties is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Microsoft Save As PDF and XPS add-ins “Disable inclusion of document properties in PDF and XPS output” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-33946r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17660'
  tag rid: 'SV-33463r1_rule'
  tag stig_id: 'DTOO206 - Office System'
  tag gtitle: 'DTOO206 - Incl. Doc. properties for PDF and XPS'
  tag fix_id: 'F-29635r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
