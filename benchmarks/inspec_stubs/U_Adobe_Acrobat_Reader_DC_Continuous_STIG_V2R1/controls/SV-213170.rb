control 'SV-213170' do
  title 'Adobe Reader DC must enable Protected Mode.'
  desc 'A threat to users of Adobe Reader DC is opening a PDF file that contains malicious executable content.

Protected mode provides a sandbox capability that prevents malicious PDF files from launching arbitrary executable files, writing to system directories or the Windows registry.

This isolation of the PDFs reduces the risk of security breaches in areas outside the sandbox.

'
  desc 'check', 'Verify the following registry configuration:

Utilizing the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown 

Value Name: bProtectedMode
Type: REG_DWORD
Value: 1

If the value for bProtectedMode is not set to “1” and Type configured to REG_DWORD or does not exist, then this is a finding.'
  desc 'fix', 'Configure the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown

Value Name: bProtectedMode
Type: REG_DWORD
Value: 1'
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Reader DC Continuous Track'
  tag check_id: 'C-14405r276728_chk'
  tag severity: 'medium'
  tag gid: 'V-213170'
  tag rid: 'SV-213170r395811_rule'
  tag stig_id: 'ARDC-CN-000015'
  tag gtitle: 'SRG-APP-000112'
  tag fix_id: 'F-14403r276729_fix'
  tag satisfies: ['SRG-APP-000112', 'SRG-APP-000206', 'SRG-APP-000207', 'SRG-APP-000209', 'SRG-APP-000210']
  tag 'documentable'
  tag legacy: ['SV-79413', 'V-64923']
  tag cci: ['CCI-001166', 'CCI-001169', 'CCI-001170', 'CCI-001662', 'CCI-001695']
  tag nist: ['SC-18 (1)', 'SC-18 (3)', 'SC-18 (4)', 'SC-18 (1)', 'SC-18 (3)']
end
