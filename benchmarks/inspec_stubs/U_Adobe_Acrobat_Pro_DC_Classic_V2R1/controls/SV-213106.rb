control 'SV-213106' do
  title 'Adobe Acrobat Pro DC Classic Default Handler changes must be disabled.'
  desc 'Acrobat Pro allows users to change the version of Acrobat Pro that is used to read PDF files. This is a risk if multiple versions of Acrobat are installed on the system and the other version has dissimilar security configurations or known vulnerabilities. When the Default PDF Handler is disabled, the end users will not be able to change the default PDF viewer.'
  desc 'check', %q(Verify the following registry configuration:

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\Software\Policies\Adobe\Adobe Acrobat\2015\FeatureLockDown

Value Name: bDisablePDFHandlerSwitching
Type: REG_DWORD
Value: 1

If the value for bDisablePDFHandlerSwitching is not set to "1" and Type is not configured to REG_DWORD or does not exist, this is a finding.

GUI path: Edit > Preferences > General > Verify the 'Select As Default PDF Handler' option is greyed out (locked).  If the option is not greyed out, this is a finding.

Admin Template path: Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Classic > Preferences > General > 'Disable PDF handler switching' must be set to 'Enabled'. 

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  desc 'fix', %q(Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\Software\Policies\Adobe\Adobe Acrobat\2015\FeatureLockDown

Value Name: bDisablePDFHandlerSwitching
Type: REG_DWORD
Value: 1

Configure the policy value for Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Classic > Preferences > General > 'Disable PDF handler switching' to 'Enabled'.  

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Professional DC Classic Track'
  tag check_id: 'C-14344r478137_chk'
  tag severity: 'low'
  tag gid: 'V-213106'
  tag rid: 'SV-213106r557504_rule'
  tag stig_id: 'AADC-CL-001280'
  tag gtitle: 'SRG-APP-000133'
  tag fix_id: 'F-14342r478138_fix'
  tag 'documentable'
  tag legacy: ['V-80137', 'SV-94841']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
