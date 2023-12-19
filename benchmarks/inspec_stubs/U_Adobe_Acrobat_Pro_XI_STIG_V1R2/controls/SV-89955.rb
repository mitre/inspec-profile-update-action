control 'SV-89955' do
  title 'The Adobe Acrobat Pro XI send and Track plugin for Outlook must be disabled.'
  desc 'When enabled, the Adobe Send and Track button appears in Outlook. When an email is composed it enables the ability to send large files as public links through Outlook. The attached files can be uploaded to the Adobe Document Cloud and public links to the files are inserted in the email body.'
  desc 'check', 'Verify the following registry configuration:

Note: The Key Name "cCloud" is not created by default in the Acrobat Pro XI install and must be created.

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown\\cCloud

Value Name: bAdobeSendPluginToggle
Type: REG_DWORD
Value: 0

If the value for bAdobeSendPluginToggle is not set to “0” and Type is not configured to REG_DWORD or does not exist, this is a finding.'
  desc 'fix', 'Configure the following registry value:

Note: The Key Name "cCloud" is not created by default in the Acrobat Pro XI install and must be created.

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\\Software\\Policies\\Adobe\\Adobe Acrobat\\11.0\\FeatureLockDown\\cCloud

Value Name: bAdobeSendPluginToggle
Type: REG_DWORD
Value: 0'
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Pro XI'
  tag check_id: 'C-75059r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75275'
  tag rid: 'SV-89955r1_rule'
  tag stig_id: 'ADBP-XI-000295'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-81891r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
