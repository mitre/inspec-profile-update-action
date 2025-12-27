control 'SV-213146' do
  title 'Adobe Reader DC must block access to Unknown Websites.'
  desc 'Because Internet access is a potential security risk, clicking any unknown website link to the Internet poses a potential security risk.

Malicious websites can transfer harmful content or silently gather data.

'
  desc 'check', 'Verify the following registry configuration:

Utilizing the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Acrobat Reader\\2015\\FeatureLockDown\\cDefaultLaunchURLPerms

Value Name: iUnknownURLPerms
Type: REG_DWORD
Value: 3

If the value for iUnknownURLPerms is not set to “3” and Type configured to REG_DWORD or does not exist, then this is a finding.'
  desc 'fix', 'Configure the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Adobe\\Acrobat Reader\\2015\\FeatureLockDown\\cDefaultLaunchURLPerms

Value Name: iUnknownURLPerms
Type: REG_DWORD
Value: 3'
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Reader DC Classic Track'
  tag check_id: 'C-14382r276581_chk'
  tag severity: 'medium'
  tag gid: 'V-213146'
  tag rid: 'SV-213146r557349_rule'
  tag stig_id: 'ARDC-CL-000030'
  tag gtitle: 'SRG-APP-000112'
  tag fix_id: 'F-14380r276582_fix'
  tag satisfies: ['SRG-APP-000112', 'SRG-APP-000206', 'SRG-APP-000207', 'SRG-APP-000209', 'SRG-APP-000210']
  tag 'documentable'
  tag legacy: ['SV-80259', 'V-65769']
  tag cci: ['CCI-001170', 'CCI-001169', 'CCI-001166', 'CCI-001662', 'CCI-001695']
  tag nist: ['SC-18 (4)', 'SC-18 (3)', 'SC-18 (1)', 'SC-18 (1)', 'SC-18 (3)']
end
