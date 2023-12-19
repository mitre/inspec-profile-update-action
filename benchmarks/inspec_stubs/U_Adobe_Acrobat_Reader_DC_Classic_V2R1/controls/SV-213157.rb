control 'SV-213157' do
  title 'Adobe Reader DC must disable access to Webmail.'
  desc 'When Webmail is disabled the user cannot configure a webmail account to send an open PDF document as an attachment. Users should have the ability to send documents as Microsoft Outlook attachments. The difference is that Outlook must be configured by the administrator on the local machine.'
  desc 'check', 'Verify the following registry configuration:

Note: The Key Name "cWebmailProfiles" is not created by default in the Adobe Reader DC install and must be created.

Utilizing the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Acrobat Reader\\2015\\FeatureLockDown\\cWebmailProfiles

Value Name: bDisableWebmail
Type: REG_DWORD
Value: 1

If the value for bDisableWebmail is not set to “1” and Type configured to REG_DWORD or does not exist, then this is a finding.'
  desc 'fix', 'Configure the following registry value:

Note: The Key Name "cWebmailProfiles" is not created by default in the Adobe Reader DC install and must be created.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Adobe\\Acrobat Reader\\2015\\FeatureLockDown\\cWebmailProfiles

Value Name: bDisableWebmail
Type: REG_DWORD
Value: 1'
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Reader DC Classic Track'
  tag check_id: 'C-14393r276614_chk'
  tag severity: 'medium'
  tag gid: 'V-213157'
  tag rid: 'SV-213157r557349_rule'
  tag stig_id: 'ARDC-CL-000090'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-14391r276615_fix'
  tag 'documentable'
  tag legacy: ['SV-80281', 'V-65791']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
