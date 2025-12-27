control 'SV-213123' do
  title 'The Adobe Acrobat Pro DC Continuous Send and Track plugin for Outlook must be disabled.'
  desc 'When enabled, the Adobe Send and Track button appears in Outlook. When an email is composed it enables the ability to send large files as public links through Outlook. The attached files can be uploaded to the Adobe Document Cloud and public links to the files are inserted in the email body.'
  desc 'check', %q(Verify the following registry configuration:

Note: The Key Name "cCloud" is not created by default in the Acrobat Pro DC install and must be created.

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cCloud

Value Name: bAdobeSendPluginToggle
Type: REG_DWORD
Value: 1

If the value for bAdobeSendPluginToggle is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.

Admin Template path: Computer Configuration > Administrative Templates > Adobe Acrobat Pro DC Continuous > Preferences > 'Send and Track plugin' must be set to 'Disabled'.)
  desc 'fix', %q(Configure the following registry value:

Note: The Key Name "cCloud" is not created by default in the Acrobat Pro DC install and must be created.

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cCloud

Value Name: bAdobeSendPluginToggle
Type: REG_DWORD
Value: 1

Configure the policy value for Computer Configuration > Administrative Templates > Adobe Acrobat Pro DC Continuous > Preferences > 'Send and Track plugin' to 'Disabled'.)
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Professional DC Continuous Track'
  tag check_id: 'C-14360r766527_chk'
  tag severity: 'medium'
  tag gid: 'V-213123'
  tag rid: 'SV-213123r766529_rule'
  tag stig_id: 'AADC-CN-000295'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-14358r766528_fix'
  tag 'documentable'
  tag legacy: ['SV-94077', 'V-79371']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
