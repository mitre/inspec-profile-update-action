control 'SV-213156' do
  title 'Adobe Reader DC must disable Adobe Send for Signature.'
  desc 'The Adobe Document Cloud sign service allows users to send documents online for signature and sign from anywhere or any device. The signed documents are stored in the Adobe Cloud. The Adobe Document Cloud sign service is a paid subscription.

When Adobe Send for Signature is disabled users will not be allowed to utilize the Adobe Document Cloud sign function.'
  desc 'check', 'Verify the following registry configuration:

Note: The Key Name "cServices" is not created by default in the Adobe Reader DC install and must be created.

Utilizing the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Acrobat Reader\\2015\\FeatureLockDown\\cServices

Value Name: bToggleAdobeSign
Type: REG_DWORD
Value: 1

If the value for bToggleAdobeSign is not set to “1” and Type configured to REG_DWORD or does not exist, then this is a finding.'
  desc 'fix', 'Configure the following registry value:

Note: The Key Name "cServices" is not created by default in the Adobe Reader DC install and must be created.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Adobe\\Acrobat Reader\\2015\\FeatureLockDown\\cServices

Value Name: bToggleAdobeSign
Type: REG_DWORD
Value: 1'
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Reader DC Classic Track'
  tag check_id: 'C-14392r276611_chk'
  tag severity: 'low'
  tag gid: 'V-213156'
  tag rid: 'SV-213156r557349_rule'
  tag stig_id: 'ARDC-CL-000085'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-14390r276612_fix'
  tag 'documentable'
  tag legacy: ['V-65789', 'SV-80279']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
