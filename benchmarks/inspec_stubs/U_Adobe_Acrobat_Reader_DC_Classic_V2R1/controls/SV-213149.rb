control 'SV-213149' do
  title 'Adobe Reader DC must disable the ability to change the Default Handler.'
  desc 'Allowing user to make changes to an application case cause a security risk.

When the Default PDF Handler is disabled, the end users will not be able to change the default PDF viewer.'
  desc 'check', 'Verify the following registry configuration:

Utilizing the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Acrobat Reader\\2015\\FeatureLockDown

Value Name: bDisablePDFHandlerSwitching
Type: REG_DWORD
Value: 1

If the value for bDisablePDFHandlerSwitching is not set to “1” and Type configured to REG_DWORD or does not exist, then this is a finding.'
  desc 'fix', 'Configure the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Adobe\\Acrobat Reader\\2015\\FeatureLockDown

Value Name: bDisablePDFHandlerSwitching
Type: REG_DWORD
Value: 1'
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Reader DC Classic Track'
  tag check_id: 'C-14385r276590_chk'
  tag severity: 'low'
  tag gid: 'V-213149'
  tag rid: 'SV-213149r557349_rule'
  tag stig_id: 'ARDC-CL-000050'
  tag gtitle: 'SRG-APP-000133'
  tag fix_id: 'F-14383r276591_fix'
  tag 'documentable'
  tag legacy: ['SV-80267', 'V-65777']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
