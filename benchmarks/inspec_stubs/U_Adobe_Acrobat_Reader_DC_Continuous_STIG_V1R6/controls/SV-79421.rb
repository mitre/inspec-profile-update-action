control 'SV-79421' do
  title 'Adobe Reader DC must prevent opening files other than PDF or FDF.'
  desc 'Attachments represent a potential security risk because they can contain malicious content, open other dangerous files, or launch applications. Certainly file types such as .bin, .exe, .bat, and so on will be recognized as threats.

This feature prevents users from opening or launching file types other than PDF or FDF and disables the menu option.

'
  desc 'check', 'Verify the following registry configuration:

Utilizing the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown

Value Name: iFileAttachmentPerms
Type: REG_DWORD
Value: 1

If the value for iFileAttachmentPerms is not set to “1” and Type configured to REG_DWORD or does not exist, then this is a finding.'
  desc 'fix', 'Configure the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown

Value Name: iFileAttachmentPerms
Type: REG_DWORD
Value: 1'
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Reader DC Continuous'
  tag check_id: 'C-65589r2_chk'
  tag severity: 'medium'
  tag gid: 'V-64931'
  tag rid: 'SV-79421r1_rule'
  tag stig_id: 'ARDC-CN-000035'
  tag gtitle: 'SRG-APP-000112'
  tag fix_id: 'F-71623r1_fix'
  tag satisfies: ['SRG-APP-000112', 'SRG-APP-000206', 'SRG-APP-000207', 'SRG-APP-000209', 'SRG-APP-000210']
  tag 'documentable'
  tag cci: ['CCI-001166', 'CCI-001169', 'CCI-001170', 'CCI-001662', 'CCI-001695']
  tag nist: ['SC-18 (1)', 'SC-18 (3)', 'SC-18 (4)', 'SC-18 (1)', 'SC-18 (3)']
end
