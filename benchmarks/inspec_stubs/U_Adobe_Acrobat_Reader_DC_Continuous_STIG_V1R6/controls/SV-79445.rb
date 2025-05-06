control 'SV-79445' do
  title 'Adobe Reader DC must disable Service Upgrades.'
  desc "By default, Adobe online services are tightly integrated into Adobe Reader DC. Disabling Service Upgrades disables both updates to the product's web-plugin components as well as all services without exception, including any online sign-in screen."
  desc 'check', 'Verify the following registry configuration:

Note: The Key Name "cServices" is not created by default in the Adobe Reader DC install and must be created.

Utilizing the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cServices

Value Name: bUpdater
Type: REG_DWORD
Value: 0

If the value for bUpdater is not set to “0” and Type configured to REG_DWORD or does not exist, then this is a finding.'
  desc 'fix', 'Configure the following registry value:

Note: The Key Name "cServices" is not created by default in the Adobe Reader DC install and must be created.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cServices

Value Name: bUpdater
Type: REG_DWORD
Value: 0'
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Reader DC Continuous'
  tag check_id: 'C-65613r2_chk'
  tag severity: 'low'
  tag gid: 'V-64955'
  tag rid: 'SV-79445r1_rule'
  tag stig_id: 'ARDC-CN-000120'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-70895r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
