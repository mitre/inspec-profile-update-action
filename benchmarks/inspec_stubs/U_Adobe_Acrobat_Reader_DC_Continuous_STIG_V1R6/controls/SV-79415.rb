control 'SV-79415' do
  title 'Adobe Reader DC must enable Protected View.'
  desc 'A threat to users of Adobe Reader DC is opening a PDF file that contains malicious executable content.

Protected view restricts Adobe Reader DC functionality, within a sandbox, when a PDF is opened from an untrusted source.

This isolation of the PDFs reduces the risk of security breaches in areas outside the sandbox.

'
  desc 'check', 'Verify the following registry configuration:

Utilizing the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown

Value Name: iProtectedView
Type: REG_DWORD
Value: 2

If the value for iProtectedView is not set to “2” and Type configured to REG_DWORD or does not exist, then this is a finding.'
  desc 'fix', 'Configure the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown

Value Name: iProtectedView
Type: REG_DWORD
Value: 2'
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Reader DC Continuous'
  tag check_id: 'C-65583r2_chk'
  tag severity: 'medium'
  tag gid: 'V-64925'
  tag rid: 'SV-79415r1_rule'
  tag stig_id: 'ARDC-CN-000020'
  tag gtitle: 'SRG-APP-000112'
  tag fix_id: 'F-70865r2_fix'
  tag satisfies: ['SRG-APP-000112', 'SRG-APP-000206', 'SRG-APP-000207', 'SRG-APP-000209', 'SRG-APP-000210']
  tag 'documentable'
  tag cci: ['CCI-001166', 'CCI-001169', 'CCI-001170', 'CCI-001662', 'CCI-001695']
  tag nist: ['SC-18 (1)', 'SC-18 (3)', 'SC-18 (4)', 'SC-18 (1)', 'SC-18 (3)']
end
