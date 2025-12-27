control 'SV-80539' do
  title 'Adobe Reader DC must disable Acrobat Upsell.'
  desc "Products that don't provide the full set of features by default provide the user the opportunity to upgrade. Acrobat Upsell displays message which encourage the user to upgrade the product. For example, Reader users can purchase additional tools and features, and Acrobat Reader users can upgrade to Acrobat Professional."
  desc 'check', 'Verify the following registry configuration:

Utilizing the Registry Editor, navigate to the following:

HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown

Value Name: bAcroSuppressUpsell
Type: REG_DWORD
Value: 1   

If the value for bAcroSuppressUpsell is not set to “1” and Type configured to REG_DWORD or does not exist, then this is a finding.'
  desc 'fix', 'Configure the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE

Registry Path: \\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown

Value Name: bAcroSuppressUpsell
Type: REG_DWORD
Value: 1'
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Reader DC Continuous'
  tag check_id: 'C-66693r4_chk'
  tag severity: 'low'
  tag gid: 'V-66049'
  tag rid: 'SV-80539r1_rule'
  tag stig_id: 'ARDC-CN-000080'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-72125r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
