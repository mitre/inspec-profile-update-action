control 'SV-213107' do
  title 'Adobe Acrobat Pro DC Classic must disable the ability to store files on Acrobat.com.'
  desc 'Adobe Acrobat Pro DC provides the ability to store PDF files on Adobe.com servers. Allowing users to store files on non-DoD systems introduces risk of data compromise.'
  desc 'check', %q(Verify the following registry configuration:

Note: The Key Name "cCloud" is not created by default in the Acrobat Pro DC install and must be created.

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\Software\Policies\Adobe\Adobe Acrobat\2015\FeatureLockDown\cCloud

Value Name: bDisableADCFileStore
Type: REG_DWORD
Value: 1

If the value for bDisableADCFileStore is not set to "1" and Type is not configured to REG_DWORD or does not exist, this is a finding.

Admin Template path: Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Classic > Preferences > 'Store files on Adobe.com' must be set to 'Disabled'.

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  desc 'fix', %q(Configure the following registry value:

Note: The Key Name "cCloud" is not created by default in the Acrobat Pro DC install and must be created.

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\Software\Policies\Adobe\Adobe Acrobat\2015\FeatureLockDown\cCloud

Value Name: bDisableADCFileStore
Type: REG_DWORD
Value: 1

Configure the policy value for Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Classic > Preferences > 'Store files on Adobe.com' to 'Disabled'.

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Professional DC Classic Track'
  tag check_id: 'C-14345r478140_chk'
  tag severity: 'medium'
  tag gid: 'V-213107'
  tag rid: 'SV-213107r557504_rule'
  tag stig_id: 'AADC-CL-001285'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-14343r478141_fix'
  tag 'documentable'
  tag legacy: ['SV-94843', 'V-80139']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
