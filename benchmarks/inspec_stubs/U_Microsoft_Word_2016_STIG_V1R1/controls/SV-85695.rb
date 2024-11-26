control 'SV-85695' do
  title 'The Save commands default file format must be configured.'
  desc 'This policy setting determines the default file format for saving files in Word. If you enable this policy setting, you can set the default file format from among the following options: - Word Document (*.docx): This option is the default configuration in Word.- Single Files Web Page (*.mht)- Web Page (*.htm; *.html)- Web Page, Filtered (*.htm, *.html)- Rich Text Format (*.rtf)- Plain Text  (*.txt)- Word 6.0/95 (*.doc)- Word 6.0/95 - Chinese (Simplified) (*.doc)- Word 6.0/95 - Chinese (Traditional) (*.doc)- Word 6.0/95 - Japanese (*.doc)- Word 6.0/95 - Korean (*.doc)- Word 97-2002 and 6.0/95 - RTF- Word 5.1 for Macintosh (*.mcw)- Word 5.0 for Macintosh (*.mcw)- Word 2.x for Windows (*.doc)- Works 4.0 for Windows (*.wps)- WordPerfect 5.x for Windows (*.doc)- WordPerfect 5.1 for DOS (*.doc)- Word Macro-Enabled Document (*.docm)- Word Template (*.dotx)- Word Macro-Enabled Template (*.dotm)- Word 97 - 2003 Document (*.doc)- Word 97 - 2003 Template (*.dot)- Word XML Document (*.xml)- Strict Open XML Document (*.docx)- OpenDocument Text (*.odt). Users can choose to save presentations or documents in a different file format than the default. If you disable or do not configure this policy setting, Word saves new files in the Office Open XML format: Word files have a .docx extension. For users who run recent versions of Word, Microsoft offers the Microsoft Office Compatibility Pack, which enables them to open and save Office Open XML files. If some users in your organization cannot install the Compatibility Pack, or are running versions of Word older than Microsoft Office 2000 with Service Pack 3, they might not be able to access Office Open XML files. This policy setting is often set in combination with the "Save As Open XML in Compatibility Mode" policy setting.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2016 -> Word Options -> Save "default file format" is set to "Enabled: Word Document (.docx)". 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\word\\options 

Criteria: If the value DefaultFormat is REG_SZ = (blank), this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2016 -> Word Options -> Save "default file format" to "Enabled: Word Document (.docx)".'
  impact 0.5
  ref 'DPMS Target Microsoft Word 2016'
  tag check_id: 'C-71499r3_chk'
  tag severity: 'medium'
  tag gid: 'V-71071'
  tag rid: 'SV-85695r1_rule'
  tag stig_id: 'DTOO139'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-77403r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
