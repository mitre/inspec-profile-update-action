control 'SV-213168' do
  title 'Adobe Reader DC must enable Enhanced Security in a Standalone Application.'
  desc 'PDFs have evolved from static pages to complex documents with features such as interactive forms, multimedia content, scripting, and other capabilities. These features leave PDFs vulnerable to malicious scripts or actions that can damage the computer or steal data. The Enhanced security feature protects the computer against these threats by blocking or selectively permitting actions for trusted locations and files.

Enhanced Security determines if a PDF is viewed within a standalone application. A threat to users of Adobe Reader DC is opening a PDF file that contains malicious executable content.

Enhanced Security “hardens” the application against risky actions: prevents cross domain access, prohibits script and data injection, blocks stream access to XObjects, silent printing, and execution of high privilege JavaScript.

'
  desc 'check', 'Verify the following registry configuration:

Utilizing the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown

Value Name: bEnhancedSecurityStandalone
Type: REG_DWORD
Value: 1

If the value for bEnhancedSecurityStandalone is not set to “1” and Type configured to REG_DWORD or does not exist, then this is a finding.'
  desc 'fix', 'Configure the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown

Value Name: bEnhancedSecurityStandalone
Type: REG_DWORD
Value: 1'
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Reader DC Continuous Track'
  tag check_id: 'C-14403r276722_chk'
  tag severity: 'medium'
  tag gid: 'V-213168'
  tag rid: 'SV-213168r395811_rule'
  tag stig_id: 'ARDC-CN-000005'
  tag gtitle: 'SRG-APP-000112'
  tag fix_id: 'F-14401r276723_fix'
  tag satisfies: ['SRG-APP-000112', 'SRG-APP-000206', 'SRG-APP-000207', 'SRG-APP-000209', 'SRG-APP-000210']
  tag 'documentable'
  tag legacy: ['V-64919', 'SV-79409']
  tag cci: ['CCI-001166', 'CCI-001169', 'CCI-001170', 'CCI-001662', 'CCI-001695']
  tag nist: ['SC-18 (1)', 'SC-18 (3)', 'SC-18 (4)', 'SC-18 (1)', 'SC-18 (3)']
end
