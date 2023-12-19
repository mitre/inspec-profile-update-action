control 'SV-213183' do
  title 'Adobe Reader DC must disable Adobe Send for Signature.'
  desc 'The Adobe Document Cloud sign service allows users to send documents online for signature and sign from anywhere or any device. The signed documents are stored in the Adobe Cloud. The Adobe Document Cloud sign service is a paid subscription.

When Adobe Send for Signature is disabled users will not be allowed to utilize the Adobe Document Cloud sign function.'
  desc 'check', 'Verify the following registry configuration:

Note: The Key Name "cServices" is not created by default in the Adobe Reader DC install and must be created.

Utilizing the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cServices

Value Name: bToggleAdobeSign
Type: REG_DWORD
Value: 1

If the value for bToggleAdobeSign is not set to “1” and Type configured to REG_DWORD or does not exist, then this is a finding.'
  desc 'fix', 'Configure the following registry value:

Note: The Key Name "cServices" is not created by default in the Adobe Reader DC install and must be created.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cServices

Value Name: bToggleAdobeSign
Type: REG_DWORD
Value: 1'
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Reader DC Continuous Track'
  tag check_id: 'C-14418r276767_chk'
  tag severity: 'low'
  tag gid: 'V-213183'
  tag rid: 'SV-213183r395853_rule'
  tag stig_id: 'ARDC-CN-000085'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-14416r276768_fix'
  tag 'documentable'
  tag legacy: ['SV-79437', 'V-64947']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
