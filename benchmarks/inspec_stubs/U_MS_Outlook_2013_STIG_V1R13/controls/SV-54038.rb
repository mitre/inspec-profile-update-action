control 'SV-54038' do
  title 'Attachments using generated name for secure temporary folders must be configured.'
  desc 'The Secure Temporary Files folder is used to store attachments when they are opened in email. By default, Outlook generates a random name for the Secure Temporary Files folder and saves it in the Temporary Internet Files folder. This setting can be used to designate a specific path and folder to use as the Secure Temporary Files folder. This configuration is not recommended, because it means that all users will have temporary Outlook files in the same predictable location, which is not as secure. If the name of this folder is well known, a malicious user or malicious code might target this location to try and gain access to attachments.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Cryptography -> Signature Status dialog box "Attachment Secure Temporary Folder" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\security\\OutlookSecureTempFolder

Criteria: If the registry key exists, this is a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Cryptography -> Signature Status dialog box "Attachment Secure Temporary Folder" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47981r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17733'
  tag rid: 'SV-54038r1_rule'
  tag stig_id: 'DTOO269'
  tag gtitle: 'DTOO269 - Attachments to Secure Temporary Folder'
  tag fix_id: 'F-46920r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
