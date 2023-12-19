control 'SV-53976' do
  title 'The prompt to display level 1 attachments must be disallowed when closing an item.'
  desc 'To protect users from viruses and other harmful files, Outlook uses two levels of security, designated Level 1 and Level 2, to restrict access to files attached to email messages or other items. Potentially harmful files can be classified into these two levels by file type extension, with all other file types considered safe.
By default, Outlook completely blocks access to Level 1 files, and requires users to save Level 2 files to disk before opening them. If this configuration is changed, users will be able to open and execute potentially dangerous attachments, which can affect their computers or compromise the confidentiality, integrity, or availability of data.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Security Form Settings -> Attachment Security "Do not prompt about Level 1 attachments when closing an item" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\security

Criteria: If the value DontPromptLevel1AttachClose is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Security Form Settings -> Attachment Security "Do not prompt about Level 1 attachments when closing an item" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47961r5_chk'
  tag severity: 'medium'
  tag gid: 'V-17601'
  tag rid: 'SV-53976r2_rule'
  tag stig_id: 'DTOO243'
  tag gtitle: 'DTOO243 - Level 1 Attachment prompt'
  tag fix_id: 'F-46871r4_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
