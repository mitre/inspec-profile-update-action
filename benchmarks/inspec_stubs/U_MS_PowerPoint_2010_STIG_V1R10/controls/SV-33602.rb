control 'SV-33602' do
  title 'Force encrypted macros to be scanned in open XML documents must be determined and configured.'
  desc 'When an Office Open XML document (Word, Excel, and PowerPoint) is rights-managed, or password-protected, any macros embedded in the document are encrypted along with the rest of the contents.  By default, these encrypted macros will be disabled unless they are scanned by antivirus software immediately before being loaded. If this default configuration is modified, Office products will not require encrypted macros to be scanned before loading. They will be handled as specified by the Office System macro security settings, which can cause macro viruses to load undetected and lead to data loss or reduced application functionality.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2010 -> PowerPoint Options -> Security “Scan encrypted macros in PowerPoint Open XML presentations” must be “Enabled (Scan encrypted macros (default)”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\powerpoint\\security

Criteria: If the value PowerPointBypassEncryptedMacroScan is REG_DWORD = 0, this not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2010 -> PowerPoint Options -> Security “Scan encrypted macros in PowerPoint Open XML presentations” to “Enabled (Scan encrypted macros (default)”.'
  impact 0.5
  ref 'DPMS Target Microsoft PowerPoint 2010'
  tag check_id: 'C-34067r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17473'
  tag rid: 'SV-33602r1_rule'
  tag stig_id: 'DTOO142 - PowerPoint'
  tag gtitle: 'DTOO142 - Force Scan Encr. Macros in open XML'
  tag fix_id: 'F-29744r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
