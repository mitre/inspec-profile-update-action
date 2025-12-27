control 'SV-79423' do
  title 'Adobe Reader DC must block Flash Content.'
  desc 'Flash content is commonly hosted on a web page, but it can also be embedded in PDF and other documents. Flash could be used to surreptitious install malware on the end-users computer.

Flash Content restricts Adobe Reader DC not to play Flash content within a PDF.

'
  desc 'check', 'Verify the following registry configuration:

Utilizing the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown

Value Name: bEnableFlash
Type: REG_DWORD
Value: 0

If the value for bEnableFlash is not set to “0” and Type configured to REG_DWORD or does not exist, then this is a finding.'
  desc 'fix', 'Configure the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown

Value Name: bEnableFlash
Type: REG_DWORD
Value: 0'
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Reader DC Continuous'
  tag check_id: 'C-65591r2_chk'
  tag severity: 'medium'
  tag gid: 'V-64933'
  tag rid: 'SV-79423r1_rule'
  tag stig_id: 'ARDC-CN-000045'
  tag gtitle: 'SRG-APP-000112'
  tag fix_id: 'F-70873r2_fix'
  tag satisfies: ['SRG-APP-000112', 'SRG-APP-000206', 'SRG-APP-000207', 'SRG-APP-000209', 'SRG-APP-000210']
  tag 'documentable'
  tag cci: ['CCI-001166', 'CCI-001169', 'CCI-001170', 'CCI-001662', 'CCI-001695']
  tag nist: ['SC-18 (1)', 'SC-18 (3)', 'SC-18 (4)', 'SC-18 (1)', 'SC-18 (3)']
end
