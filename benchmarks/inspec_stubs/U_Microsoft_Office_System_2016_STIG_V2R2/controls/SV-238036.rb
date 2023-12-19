control 'SV-238036' do
  title 'Inclusion of document properties for PDF and XPS output must be disallowed.'
  desc 'This policy setting controls whether document metadata can be saved in PDF and XPS documents. If you enable this policy setting, document properties metadata is not exported to PDF and XPS files. If you disable this policy setting, document properties metadata will always be saved with PDF and XPS files, and users will not be able to override this configuration. If you do not configure this policy setting, if the Microsoft Save as PDF or XPS Add-in for Microsoft Office Programs add-in is installed, document properties are saved as metadata when users save files using the PDF or XPS or Publish as PDF or XPS commands in Access, Excel, InfoPath, PowerPoint, and Word, unless the "Document properties" option is unchecked in the Options dialog.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Microsoft Save As PDF and XPS add-ins "Disable inclusion of document properties in PDF and XPS output" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\common\\fixedformat

Criteria: If the value DisableFixedFormatDocProperties is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Microsoft Save As PDF and XPS add-ins "Disable inclusion of document properties in PDF and XPS output" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2016'
  tag check_id: 'C-41246r650673_chk'
  tag severity: 'medium'
  tag gid: 'V-238036'
  tag rid: 'SV-238036r650675_rule'
  tag stig_id: 'DTOO206'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-41205r650674_fix'
  tag 'documentable'
  tag legacy: ['SV-85507', 'V-70883']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
