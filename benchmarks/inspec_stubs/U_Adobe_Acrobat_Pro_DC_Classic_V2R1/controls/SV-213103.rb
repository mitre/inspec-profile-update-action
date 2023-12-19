control 'SV-213103' do
  title 'Adobe Acrobat Pro DC Classic Protected Mode must be enabled.'
  desc %q(Protected Mode is a "sandbox" that is essentially a read-only mode.  When enabled, Acrobat allows the execution environment of untrusted PDF's and the processes the PDF may invoke but also presumes all PDFs are potentially malicious and confines processing to a restricted sandbox.)
  desc 'check', %q(Verify the following registry configuration:

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\Software\Policies\Adobe\Adobe Acrobat\2015\FeatureLockDown

Value Name: bProtectedMode
Type: REG_DWORD
Value: 1

If the value for bProtectedMode is not set to "1" and Type is not configured to REG_DWORD or does not exist, this is a finding.

Admin Template path: Computer Configuration > Administrative Templates > Adobe Acrobat Pro DC Classic > Preferences > 'Protected Mode' must be set to 'Enabled'.

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  desc 'fix', %q(Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\Software\Policies\Adobe\Adobe Acrobat\2015\FeatureLockDown

Value Name: bProtectedMode
Type: REG_DWORD
Value: 1

Configure the policy value for Computer Configuration > Administrative Templates > Adobe Acrobat Pro DC Classic > Preferences > 'Protected Mode' to 'Enabled'.

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Professional DC Classic Track'
  tag check_id: 'C-14341r478131_chk'
  tag severity: 'medium'
  tag gid: 'V-213103'
  tag rid: 'SV-213103r557504_rule'
  tag stig_id: 'AADC-CL-001010'
  tag gtitle: 'SRG-APP-000431'
  tag fix_id: 'F-14339r478132_fix'
  tag 'documentable'
  tag legacy: ['SV-94835', 'V-80131']
  tag cci: ['CCI-002530']
  tag nist: ['SC-39']
end
