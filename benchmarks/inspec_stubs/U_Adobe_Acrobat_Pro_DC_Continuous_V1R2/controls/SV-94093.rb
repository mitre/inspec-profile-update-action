control 'SV-94093' do
  title 'Adobe Acrobat Pro DC Continuous must disable the ability to store files on Acrobat.com.'
  desc 'Adobe Acrobat Pro DC provides the ability to store PDF files on Adobe.com servers. Allowing users to store files on non-DoD systems introduces risk of data compromise.'
  desc 'check', %q(Verify the following registry configuration:

Note: The Key Name "cCloud" is not created by default in the Acrobat Pro DC install and must be created.

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cCloud

Value Name: bDisableADCFileStore
Type: REG_DWORD
Value: 1

If the value for bDisableADCFileStore is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.

Admin Template path: Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Continuous > Preferences > 'Store files on Adobe.com' must be set to 'Disabled'.

This policy setting requires the installation of the AcrobatProDCContinuous custom templates included with the STIG package. "AcrobatProDCContinuous.admx" and "AcrobatProDCContinuous.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  desc 'fix', %q(Configure the following registry value:

Note: The Key Name "cCloud" is not created by default in the Acrobat Pro DC install and must be created.

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\Software\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cCloud

Value Name: bDisableADCFileStore
Type: REG_DWORD
Value: 1

Configure the policy value for Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Continuous > Preferences > 'Store files on Adobe.com' to 'Disabled'.

This policy setting requires the installation of the AcrobatProDCContinuous custom templates included with the STIG package. "AcrobatProDCContinuous.admx" and "AcrobatProDCContinuous.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Pro DC Continuous'
  tag check_id: 'C-79001r4_chk'
  tag severity: 'medium'
  tag gid: 'V-79387'
  tag rid: 'SV-94093r1_rule'
  tag stig_id: 'AADC-CN-001285'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-86159r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
