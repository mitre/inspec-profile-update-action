control 'SV-79435' do
  title 'Adobe Reader DC must disable 3rd Party Web Connectors.'
  desc 'When 3rd Party Web Connectors are disabled it prevents the configuration of Adobe Reader DC access to third party services for file storage.'
  desc 'check', 'Verify the following registry configuration:

Note: The Key Name "cServices" is not created by default in the Adobe Reader DC install and must be created.

Utilizing the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cServices

Value Name: bToggleWebConnectors
Type: REG_DWORD
Value: 1

If the value for bToggleWebConnectors is not set to “1” and Type configured to REG_DWORD or does not exist, then this is a finding.'
  desc 'fix', 'Configure the following registry value:

Note: The Key Name "cServices" is not created by default in the Adobe Reader DC install and must be created.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cServices

Value Name: bToggleWebConnectors
Type: REG_DWORD
Value: 1'
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Reader DC Continuous'
  tag check_id: 'C-65603r2_chk'
  tag severity: 'medium'
  tag gid: 'V-64945'
  tag rid: 'SV-79435r1_rule'
  tag stig_id: 'ARDC-CN-000075'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-70885r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
