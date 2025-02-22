control 'SV-53989' do
  title 'Level 2 file extensions must be blocked and not removed.'
  desc %q(Malicious code is often spread through email. Some viruses have the ability to send copies of themselves to other people in the victim's Address Book or Contacts list, and such potentially harmful files can affect the computers of unwary recipients.
Outlook uses two levels of security to restrict users' access to files attached to email messages or other items. Files with specific extensions can be categorized as Level 1 (users cannot view the file) or Level 2 (users can open the file after saving it to disk). Users can freely open files of types that are not categorized as Level 1 or Level 2.
By default, Outlook classifies a number of potentially harmful file types as Level 1. (See Attachment file types restricted by Outlook for the complete list.) Outlook does not classify any file types as Level 2 by default, so this setting is not particularly useful in isolation. Typically, if there are extensions on the Level 2 list they would have been added by using the "Add file extensions to block as Level 2" setting, through which they can be removed.
The combined lists of blocked and restricted file extensions that Outlook uses are actually built by combining various policies together. If a machine policy classifies an extension as Level 2, this setting could be used to remove the extension from the list in some situations. As with Level 1 extensions, though, removing restrictions on potentially dangerous extensions can make it easier for users to open dangerous files, which can significantly reduce security.)
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2013 >> Security >> Security Form Settings >> Attachment Security "Remove file extensions blocked as Level 2" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\security\\

Criteria: If the registry value “FileExtensionsRemoveLevel2” exists, this is a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2013 >> Security >> Security Form Settings >> Attachment Security "Remove file extensions blocked as Level 2" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47963r2_chk'
  tag severity: 'medium'
  tag gid: 'V-17775'
  tag rid: 'SV-53989r2_rule'
  tag stig_id: 'DTOO245'
  tag gtitle: 'DTOO245 - Lvl 2 File Extensions'
  tag fix_id: 'F-46881r3_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
