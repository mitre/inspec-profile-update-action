control 'SV-213177' do
  title 'Adobe Reader DC must disable the Adobe Send and Track plugin for Outlook.'
  desc 'When enabled, Adobe Send and Track button appears in Outlook. When an email is composed it enables the ability to send large files as public links through Outlook. The attached files can be uploaded to the Adobe Document Cloud and public links to the files are inserted in the email body.'
  desc 'check', %q(Verify the following registry configuration:

Note: The Key Name "cCloud" is not created by default in the Adobe Reader DC install and must be created.

Utilizing the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cCloud

Value Name: bAdobeSendPluginToggle
Type: REG_DWORD
Value: 1

If the value for bAdobeSendPluginToggle is not set to “1” and Type configured to REG_DWORD or does not exist, then this is a finding.

Admin Template path: Computer Configuration > Administrative Templates > Adobe Reader DC Continuous > Preferences > 'Send and Track plugin' must be set to 'Disabled'.)
  desc 'fix', %q(Configure the following registry value:

Note: The Key Name "cCloud" is not created by default in the Adobe Reader DC install and must be created.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown\cCloud

Value Name: bAdobeSendPluginToggle
Type: REG_DWORD
Value: 1

Configure the policy value for Computer Configuration > Administrative Templates > Adobe Reader DC Continuous > Preferences > 'Send and Track plugin' to 'Disabled'.)
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Reader DC Continuous Track'
  tag check_id: 'C-14412r766572_chk'
  tag severity: 'low'
  tag gid: 'V-213177'
  tag rid: 'SV-213177r766574_rule'
  tag stig_id: 'ARDC-CN-000055'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-14410r766573_fix'
  tag 'documentable'
  tag legacy: ['SV-79427', 'V-64937']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
