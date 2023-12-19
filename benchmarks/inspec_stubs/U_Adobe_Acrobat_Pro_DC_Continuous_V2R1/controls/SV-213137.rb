control 'SV-213137' do
  title 'Adobe Acrobat Pro DC Continuous SharePoint and Office365 access must be disabled.'
  desc 'Both SharePoint and Office365 configurations are shared in one setting. Disabling this setting removes the user’s ability to use both SharePoint and Office365 cloud features and functions. If the user is allowed to store files on public cloud services, there is a risk of data compromise.'
  desc 'check', %q(NOTE: If configured to an approved DoD SharePoint Server, this is NA.

Verify the following registry configuration:

Note: The Key Name "cSharePoint" is not created by default in the Acrobat Pro DC install and must be created.

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cSharePoint

Value Name: bDisableSharePointFeatures
Type: REG_DWORD
Value: 1

If the value for bDisableSharePointFeatures is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.

Admin Template path: Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Continuous > Preferences > 'SharePoint and Office 365 access' must be set to 'Disabled'.)
  desc 'fix', %q(Configure the following registry value:

Note: The Key Name "cSharePoint" is not created by default in the Acrobat Pro DC install and must be created.

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cSharePoint

Value Name: bDisableSharePointFeatures
Type: REG_DWORD
Value: 1

Configure the policy value for Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Continuous > Preferences > 'SharePoint and Office 365 access' to 'Disabled'.)
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Professional DC Continuous Track'
  tag check_id: 'C-14374r766563_chk'
  tag severity: 'low'
  tag gid: 'V-213137'
  tag rid: 'SV-213137r766565_rule'
  tag stig_id: 'AADC-CN-001315'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-14372r766564_fix'
  tag 'documentable'
  tag legacy: ['SV-94105', 'V-79399']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
