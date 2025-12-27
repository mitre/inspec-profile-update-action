control 'SV-55898' do
  title 'Level 1 file extensions must be blocked and not removed.'
  desc "Malicious code is often spread through e-mail. Some viruses have the ability to send copies of themselves to other people in the victim's Address Book or Contacts list, and such potentially harmful files can affect the computers of unwary recipients."
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2013 >> Security >> Security Form Settings >> Attachment Security "Remove file extensions blocked as Level 1" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\security

Criteria: HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\security\\

Criteria: If the registry value “FileExtensionsRemoveLevel1” exists, this is a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2013 >> Security >> Security Form Settings >> Attachment Security "Remove file extensions blocked as Level 1" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47962r4_chk'
  tag severity: 'medium'
  tag gid: 'V-17774'
  tag rid: 'SV-55898r2_rule'
  tag stig_id: 'DTOO244'
  tag gtitle: 'DTOO244 - Lvl 1 File extensions'
  tag fix_id: 'F-46876r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
