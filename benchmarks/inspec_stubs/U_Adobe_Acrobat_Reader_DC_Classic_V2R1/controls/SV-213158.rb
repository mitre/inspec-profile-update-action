control 'SV-213158' do
  title 'Adobe Reader DC must disable Online SharePoint Access.'
  desc "Disabling SharePoint disables or removes the user’s ability to add a SharePoint account access controls the application's ability to detect that a file came from a SharePoint server, and disables the check-out prompt."
  desc 'check', 'Verify the following registry configuration:

If configured to an approved DoD SharePoint Server, this is NA.

Note: The Key Name "cSharePoint" is not created by default in the Adobe Reader DC install and must be created.

Utilizing the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Acrobat Reader\\2015\\FeatureLockDown\\cSharePoint

Value Name: bDisableSharePointFeatures
Type: REG_DWORD
Value: 1

If the value for bDisableSharePointFeatures is not set to “1” and Type configured to REG_DWORD or does not exist, then this is a finding.'
  desc 'fix', 'Configure the following registry value:

Note: The Key Name "cSharePoint" is not created by default in the Adobe Reader DC install and must be created.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Adobe\\Acrobat Reader\\2015\\FeatureLockDown\\cSharePoint

Value Name: bDisableSharePointFeatures
Type: REG_DWORD
Value: 1'
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Reader DC Classic Track'
  tag check_id: 'C-14394r276617_chk'
  tag severity: 'medium'
  tag gid: 'V-213158'
  tag rid: 'SV-213158r557349_rule'
  tag stig_id: 'ARDC-CL-000100'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-14392r276618_fix'
  tag 'documentable'
  tag legacy: ['V-65793', 'SV-80283']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
