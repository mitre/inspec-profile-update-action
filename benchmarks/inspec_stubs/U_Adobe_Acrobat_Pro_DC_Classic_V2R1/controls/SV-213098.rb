control 'SV-213098' do
  title 'Adobe Acrobat Pro DC Classic must be configured to block Flash Content.'
  desc 'Flash has a long history of vulnerabilities.  Although Flash is no longer provided with Acrobat, if the system has Flash installed, a malicious PDF could execute code on the system.  Configuring Flash to run from a privileged location limits the execution capability of untrusted Flash content that may be embedded in the PDF.'
  desc 'check', %q(Verify the following registry configuration:

Using the Registry Editor, navigate to the following: HKEY_LOCAL_MACHINE\Software\Policies\Adobe\Adobe Acrobat\2015\FeatureLockDown

Value Name: bEnableFlash
Type: REG_DWORD
Value: 0

If the value for bEnableFlash is not set to "0" and Type is not configured to REG_DWORD or does not exist, this is a finding.

Admin Template path: Computer Configuration > Administrative Templates > Adobe Acrobat Pro DC Classic > Preferences > 'Enable Flash' must be set to 'Disabled'.

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  desc 'fix', %q(Configure the following registry value:

Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\Software\Policies\Adobe\Adobe Acrobat\2015\FeatureLockDown

Value Name: bEnableFlash
Type: REG_DWORD
Value: 0

Configure the policy value for Computer Configuration > Administrative Templates > Adobe Acrobat Pro DC Classic > Preferences > 'Enable Flash' to 'Disabled'.

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Professional DC Classic Track'
  tag check_id: 'C-14336r478119_chk'
  tag severity: 'medium'
  tag gid: 'V-213098'
  tag rid: 'SV-213098r557504_rule'
  tag stig_id: 'AADC-CL-000290'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-14334r478120_fix'
  tag 'documentable'
  tag legacy: ['SV-94825', 'V-80121']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
