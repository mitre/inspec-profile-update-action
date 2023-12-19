control 'SV-213155' do
  title 'Adobe Reader DC must disable Acrobat Upsell.'
  desc 'Products that don’t provide the full set of features by default provide the user the opportunity to upgrade. Acrobat Upsell displays message which encourage the user to upgrade the product. For example, Reader users can purchase additional tools and features, and Acrobat Reader users can upgrade to Acrobat Professional.'
  desc 'check', 'Verify the following registry configuration:

Utilizing the Registry Editor, navigate to the following: 
HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Acrobat Reader\\2015\\FeatureLockDown 

Value Name: bAcroSuppressUpsell
Type: REG_DWORD
Value: 1

If the value for bAcroSuppressUpsell is not set to “1” and Type configured to REG_DWORD or does not exist, then this is a finding.'
  desc 'fix', 'Configure the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Adobe\\Acrobat Reader\\2015\\FeatureLockDown 

Value Name: bAcroSuppressUpsell
Type: REG_DWORD
Value: 1'
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Reader DC Classic Track'
  tag check_id: 'C-14391r276608_chk'
  tag severity: 'low'
  tag gid: 'V-213155'
  tag rid: 'SV-213155r557349_rule'
  tag stig_id: 'ARDC-CL-000080'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-14389r276609_fix'
  tag 'documentable'
  tag legacy: ['SV-80305', 'V-65815']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
