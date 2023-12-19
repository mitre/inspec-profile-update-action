control 'SV-213151' do
  title 'Adobe Reader DC must disable all service access to Document Cloud Services.'
  desc 'By default, Adobe online services are tightly integrated in Adobe Reader DC. With the integration of Adobe Document Cloud, disabling this feature prevents the risk of additional attack vectors.

Within Adobe Reader DC, the Adobe Cloud resources require a paid subscription for each service.'
  desc 'check', 'Verify the following registry configuration:

Note: The Key Name "cServices" is not created by default in the Adobe Reader DC install and must be created.

Utilizing the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Acrobat Reader\\2015\\FeatureLockDown\\cServices

Value Name: bToggleAdobeDocumentServices
Type: REG_DWORD
Value: 1

If the value for bToggleAdobeDocumentServices is not set to “1” and Type configured to REG_DWORD or does not exist, then this is a finding.'
  desc 'fix', 'Configure the following registry value:

Note: The Key Name "cServices" is not created by default in the Adobe Reader DC install and must be created.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Adobe\\Acrobat Reader\\2015\\FeatureLockDown\\cServices

Value Name: bToggleAdobeDocumentServices
Type: REG_DWORD
Value: 1'
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Reader DC Classic Track'
  tag check_id: 'C-14387r276596_chk'
  tag severity: 'medium'
  tag gid: 'V-213151'
  tag rid: 'SV-213151r557349_rule'
  tag stig_id: 'ARDC-CL-000060'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-14385r276597_fix'
  tag 'documentable'
  tag legacy: ['V-65781', 'SV-80271']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
