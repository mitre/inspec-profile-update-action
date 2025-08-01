control 'SV-89973' do
  title 'Adobe Acrobat Pro XI Default Handler changes must be disabled.'
  desc 'Acrobat Pro allows users to change the version of Acrobat Pro that is used to read PDF files. This is a risk if multiple versions of Acrobat are installed on the system and the other version has dissimilar security configurations or known vulnerabilities. When the Default PDF Handler is disabled, the end users will not be able to change the default PDF viewer.'
  desc 'check', 'Verify the following registry configuration:

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown

Value Name: bDisablePDFHandlerSwitching
Type: REG_DWORD
Value: 1

If the value for bDisablePDFHandlerSwitching is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.'
  desc 'fix', 'Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown

Value Name: bDisablePDFHandlerSwitching
Type: REG_DWORD
Value: 1'
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Pro XI'
  tag check_id: 'C-75077r1_chk'
  tag severity: 'low'
  tag gid: 'V-75293'
  tag rid: 'SV-89973r1_rule'
  tag stig_id: 'ADBP-XI-001280'
  tag gtitle: 'SRG-APP-000133'
  tag fix_id: 'F-81909r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
