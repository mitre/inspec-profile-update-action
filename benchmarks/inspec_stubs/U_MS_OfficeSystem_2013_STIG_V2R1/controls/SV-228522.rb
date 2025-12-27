control 'SV-228522' do
  title 'Inclusion of document properties for PDF and XPS output must be disallowed.'
  desc 'If the Microsoft Save as PDF or XPS Add-in for Microsoft Office Programs is installed, document properties are saved as metadata when users save or publish files using the PDF or XPS commands in Access 2013, Excel 2013, InfoPath 2013, PowerPoint 2013, and Word 2013 using the PDF or XPS or Publish. If this metadata contains sensitive information, saving it with the file could compromise security.'
  desc 'check', %q(Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2013 >> Microsoft Save As PDF and XPS add-ins "Disable inclusion of document properties in PDF and XPS output" is set to "Enabled".

Use the Windows Registry Editor to navigate to the following HKCU\Software\Policies\Microsoft\Office\15.0\common\fixedformat

If the value 'DisableFixedFormatDocProperties' is REG_DWORD = 1, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2013 -> Microsoft Save As PDF and XPS add-ins "Disable inclusion of document properties in PDF and XPS output" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30755r498844_chk'
  tag severity: 'medium'
  tag gid: 'V-228522'
  tag rid: 'SV-228522r508020_rule'
  tag stig_id: 'DTOO206'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30740r498845_fix'
  tag 'documentable'
  tag legacy: ['SV-52753', 'V-17660']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
