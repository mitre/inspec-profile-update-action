control 'SV-213099' do
  title 'The Adobe Acrobat Pro DC Classic Send and Track plugin for Outlook must be disabled.'
  desc 'When enabled, the Adobe Send and Track button appears in Outlook. When an email is composed it enables the ability to send large files as public links through Outlook. The attached files can be uploaded to the Adobe Document Cloud and public links to the files are inserted in the email body.'
  desc 'check', %q(Verify the following registry configuration:

Note: The Key Name "cCloud" is not created by default in the Acrobat Pro DC install and must be created.

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\Software\Policies\Adobe\Adobe Acrobat\2015\FeatureLockDown\cCloud

Value Name: bAdobeSendPluginToggle
Type: REG_DWORD
Value: 1

If the value for bAdobeSendPluginToggle is not set to "1" and Type is not configured to REG_DWORD or does not exist, this is a finding.

Admin Template path: Computer Configuration > Administrative Templates > Adobe Acrobat Pro DC Classic > Preferences > 'Send and Track plugin' must be set to 'Disabled'.

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  desc 'fix', %q(Configure the following registry value:

Note: The Key Name "cCloud" is not created by default in the Acrobat Pro DC install and must be created.

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\Software\Policies\Adobe\Adobe Acrobat\2015\FeatureLockDown\cCloud

Value Name: bAdobeSendPluginToggle
Type: REG_DWORD
Value: 1
Configure the policy value for Computer Configuration > Administrative Templates > Adobe Acrobat Pro DC Classic > Preferences > 'Send and Track plugin' to 'Disabled'.

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Professional DC Classic Track'
  tag check_id: 'C-14337r478122_chk'
  tag severity: 'medium'
  tag gid: 'V-213099'
  tag rid: 'SV-213099r557504_rule'
  tag stig_id: 'AADC-CL-000295'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-14335r478123_fix'
  tag 'documentable'
  tag legacy: ['V-80123', 'SV-94827']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
