control 'SV-89985' do
  title 'Adobe Acrobat Pro XI SharePoint and Office365 Access must be disabled.'
  desc 'Both SharePoint and Office365 configurations are shared in one setting. Disabling this setting removes the user’s ability to use both SharePoint and Office365 cloud features and functions. If the user is allowed to store files on public cloud services, there is a risk of data compromise.'
  desc 'check', 'Verify the following registry configuration:

Note: The Key Name "cSharePoint" is not created by default in the Acrobat Pro XI install and must be created.

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown\\cSharePoint

Value Name: bDisableSharePointFeatures
Type: REG_DWORD
Value: 1

If the value for bDisableSharePointFeatures is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.'
  desc 'fix', 'Configure the following registry value:

Note: The Key Name "cSharePoint" is not created by default in the Acrobat Pro XI install and must be created.

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\\Software\\Policies\\Adobe\\Acrobat Reader\\11.0\\FeatureLockDown\\cSharePoint

Value Name: bDisableSharePointFeatures
Type: REG_DWORD
Value: 1'
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Pro XI'
  tag check_id: 'C-75089r2_chk'
  tag severity: 'low'
  tag gid: 'V-75305'
  tag rid: 'SV-89985r1_rule'
  tag stig_id: 'ADBP-XI-001315'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-81921r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
