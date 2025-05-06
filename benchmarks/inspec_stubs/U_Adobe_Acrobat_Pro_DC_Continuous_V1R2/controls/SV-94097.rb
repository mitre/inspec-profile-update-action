control 'SV-94097' do
  title 'Adobe Acrobat Pro DC Continuous Repair Installation must be disabled.'
  desc 'When Repair Installation is disabled the user does not have the option (Help Menu) or ability to repair an Adobe Acrobat Pro DC install. Ability to repair includes the risk that established security settings could be overwritten.'
  desc 'check', %q(Verify the following registry configuration:

Using the Registry Editor, navigate to the following: 

For 32 bit:
HKEY_LOCAL_MACHINE\Software\Adobe\Adobe Acrobat\DC\Installer

For 64 bit:
HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer

Value Name: DisableMaintenance
Type: REG_DWORD
Value: 1

If the value for DisableMaintenance is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.

GUI path: Help > Verify the option 'Repair Installation' is greyed out (locked). If the option is not greyed out, this is a finding.

Admin Template path: Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Continuous > Preferences > Help > 'Repair Installation on 32/64 bit' must be set to 'Disabled'.

This policy setting requires the installation of the AcrobatProDCContinuous custom templates included with the STIG package. "AcrobatProDCContinuous.admx" and "AcrobatProDCContinuous.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  desc 'fix', %q(Configure the following registry value:

For 32 bit:
Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\Software\Adobe\Adobe Acrobat\DC\Installer

For 64 bit:
Registry Hive:
HKEY_LOCAL_MACHINE
Registry Path:
\SOFTWARE\Wow6432Node\Adobe\Adobe Acrobat\DC\Installer

Value Name: DisableMaintenance
Type: REG_DWORD
Value: 1

Configure the policy value for Computer Configuration > Administrative Template > Adobe Acrobat Pro DC Continuous > Preferences > Help > 'Repair Installation on 32/64 bit' to 'Disabled'.

This policy setting requires the installation of the AcrobatProDCContinuous custom templates included with the STIG package. "AcrobatProDCContinuous.admx" and "AcrobatProDCContinuous.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  impact 0.3
  ref 'DPMS Target Adobe Acrobat Pro DC Continuous'
  tag check_id: 'C-79005r4_chk'
  tag severity: 'low'
  tag gid: 'V-79391'
  tag rid: 'SV-94097r1_rule'
  tag stig_id: 'AADC-CN-001295'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-86163r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
