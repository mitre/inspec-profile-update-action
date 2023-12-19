control 'SV-213150' do
  title 'Adobe Reader DC must disable the Adobe Send and Track plugin for Outlook.'
  desc 'When enabled, Adobe Send and Track button appears in Outlook. When an email is composed it enables the ability to send large files as public links through Outlook. The attached files can be uploaded to the Adobe Document Cloud and public links to the files are inserted in the email body.'
  desc 'check', %q(Verify the following registry configuration:

Note: The Key Name "cCloud" is not created by default in the Adobe Reader DC install and must be created.

Utilizing the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\Software\Policies\Adobe\Acrobat Reader\2015\FeatureLockDown\cCloud

Value Name: bAdobeSendPluginToggle
Type: REG_DWORD
Value: 1

If the value for bAdobeSendPluginToggle is not set to “1” and Type configured to REG_DWORD or does not exist, then this is a finding.

Admin Template path: Computer Configuration > Administrative Templates > Adobe Reader DC Classic > Preferences > 'Send and Track plugin' must be set to 'Disabled'.

This policy setting requires the installation of the AcrobatDCClassic custom templates included with the STIG package. "AcrobatDCClassic.admx" and "AcrobatDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  desc 'fix', %q(Configure the following registry value:

Note: The Key Name "cCloud" is not created by default in the Adobe Reader DC install and must be created.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \Software\Policies\Adobe\Acrobat Reader\2015\FeatureLockDown\cCloud

Value Name: bAdobeSendPluginToggle
Type: REG_DWORD
Value: 1

Configure the policy value for Computer Configuration > Administrative Templates > Adobe Reader DC Classic > Preferences > 'Send and Track plugin' to 'Disabled'.

This policy setting requires the installation of the AcrobatDCClassic custom templates included with the STIG package. "AcrobatDCClassic.admx" and "AcrobatDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Reader DC Classic Track'
  tag check_id: 'C-14386r276593_chk'
  tag severity: 'low'
  tag gid: 'V-213150'
  tag rid: 'SV-213150r557349_rule'
  tag stig_id: 'ARDC-CL-000055'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-14384r276594_fix'
  tag 'documentable'
  tag legacy: ['SV-80269', 'V-65779']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
