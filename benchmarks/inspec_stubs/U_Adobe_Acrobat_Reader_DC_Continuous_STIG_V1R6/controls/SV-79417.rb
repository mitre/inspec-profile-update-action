control 'SV-79417' do
  title 'Adobe Reader DC must Block Websites.'
  desc 'Clicking any link to the Internet poses a potential security risk. Malicious websites can transfer harmful content or silently gather data. Acrobat Reader documents can connect to websites which can pose a potential threat to DoD systems and that functionality must be blocked. However, PDF document workflows that are trusted (e.g., DoD-created) can benefit from leveraging legitimate website access with minimal risk. Therefore, the ISSO may approve of website access and accept the risk if the access provides benefit and is a trusted site or the risk associated with accessing the site has been mitigated.

Adobe Reader must block access to all websites that are not specifically allowed by ISSO risk acceptance.

'
  desc 'check', 'Verify the following registry configuration:

Utilizing the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cDefaultLaunchURLPerms

Value Name: iURLPerms
Type: REG_DWORD
Value: 1

Value: 0 - only with a documented ISSO risk acceptance

If the value for “iURLPerms” is set to “0” and a documented ISSO risk acceptance approving access to websites is provided, this is not a finding.

If the value for “iURLPerms” is not set to “1” and “Type” configured to “REG_DWORD” or does not exist, this is a finding.'
  desc 'fix', 'Configure the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path:
\\Software\\Policies\\Adobe\\Acrobat Reader\\DC\\FeatureLockDown\\cDefaultLaunchURLPerms

Value Name: iURLPerms
Type: REG_DWORD
Value: 1

If configuring system to allow access to websites, obtain documented ISSO approvals and risk acceptance and set “iURLPerms” to “0”.'
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Reader DC Continuous'
  tag check_id: 'C-65585r3_chk'
  tag severity: 'medium'
  tag gid: 'V-64927'
  tag rid: 'SV-79417r2_rule'
  tag stig_id: 'ARDC-CN-000025'
  tag gtitle: 'SRG-APP-000112'
  tag fix_id: 'F-70867r3_fix'
  tag satisfies: ['SRG-APP-000112', 'SRG-APP-000206', 'SRG-APP-000207', 'SRG-APP-000209', 'SRG-APP-000210']
  tag 'documentable'
  tag cci: ['CCI-001166', 'CCI-001169', 'CCI-001170', 'CCI-001662', 'CCI-001695']
  tag nist: ['SC-18 (1)', 'SC-18 (3)', 'SC-18 (4)', 'SC-18 (1)', 'SC-18 (3)']
end
