control 'SV-53598' do
  title 'Word must be configured to warn when opening a document with custom XML markup.'
  desc 'This policy setting specifies how Word behaves when opening a document that contains custom XML markup. Versions of Word that are distributed by Microsoft after January 10, 2010 no longer read the custom XML markup that may be contained within (.docx, .docm, .dotx, .dotm or .xml files. The new versions of Word 2007, Word 2010, and Word 2013 can still open these files, but any custom XML markup is removed. Configuring this setting will prompt the user with a warning, notifying of the lost of the XML markup. While this is the default setting, explicitly configuring the setting will ensure users are prompted.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2013 -> Word Options -> Advanced -> "Custom markup warning" is set to "Enabled: Prompt".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\word\\options

Criteria: If the value custommarkupwarning is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2013 -> Word Options -> Advanced -> "Custom markup warning" to "Enabled: Prompt".'
  impact 0.5
  ref 'DPMS Target Microsoft Word 2013'
  tag check_id: 'C-47743r1_chk'
  tag severity: 'medium'
  tag gid: 'V-41147'
  tag rid: 'SV-53598r1_rule'
  tag stig_id: 'DTOO426'
  tag gtitle: 'DTOO426 - Custom XML markup warning'
  tag fix_id: 'F-46523r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
