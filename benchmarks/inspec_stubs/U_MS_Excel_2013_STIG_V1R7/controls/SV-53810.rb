control 'SV-53810' do
  title 'The scanning of encrypted macros in open XML documents must be enforced.'
  desc 'When an Office Open XML document (Word, Excel, and PowerPoint) is rights-managed, or password-protected, any macros embedded in the document are encrypted along with the rest of the contents.  By default, these encrypted macros will be disabled unless they are scanned by antivirus software immediately before being loaded. If this default configuration is modified, Office products will not require encrypted macros to be scanned before loading. They will be handled as specified by the Office System macro security settings, which can cause macro viruses to load undetected and lead to data loss or reduced application functionality.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Excel Options -> Security "Scan encrypted macros in Excel Open XML workbooks" is set to "Enabled: Scan encrypted macros (default)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\excel\\security

Criteria: If the value ExcelBypassEncryptedMacroScan is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Excel Options -> Security "Scan encrypted macros in Excel Open XML workbooks" to "Enabled: Scan encrypted macros (default)".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2013'
  tag check_id: 'C-47882r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17473'
  tag rid: 'SV-53810r1_rule'
  tag stig_id: 'DTOO142'
  tag gtitle: 'DTOO142 - Force Scan Encr. Macros in open XML'
  tag fix_id: 'F-46718r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
