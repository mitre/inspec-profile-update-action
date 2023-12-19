control 'SV-94081' do
  title 'Adobe Acrobat Pro DC Continuous FIPS mode must be enabled.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', %q(Verify the following registry configuration:

Using the Registry Editor, navigate to the following: HKEY_CURRENT_USER\Software\Adobe\Adobe Acrobat\DC\AVGeneral

Value Name: bFIPSMode
Type: REG_DWORD
Value: 1

If the value for bFIPSMode is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.

Admin Template path: User Configuration > Administrative Templates > Adobe Acrobat Pro DC Continuous > Preferences > 'Enable FIPS' must be set to 'Enabled'.

This policy setting requires the installation of the AcrobatProDCContinuous custom templates included with the STIG package. "AcrobatProDCContinuous.admx" and "AcrobatProDCContinuous.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  desc 'fix', %q(Configure the following registry value:

Registry Hive:
HKEY_CURRENT_USER
Registry Path:
\Software\Adobe\Adobe Acrobat\DC\AVGeneral

Value Name: bFIPSMode
Type: REG_DWORD
Value: 1
Configure the policy value for User Configuration > Administrative Templates > Adobe Acrobat Pro DC Continuous > Preferences > 'Enable FIPS' to 'Enabled'.

This policy setting requires the installation of the AcrobatProDCContinuous custom templates included with the STIG package. "AcrobatProDCContinuous.admx" and "AcrobatProDCContinuous.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Pro DC Continuous'
  tag check_id: 'C-78989r3_chk'
  tag severity: 'medium'
  tag gid: 'V-79375'
  tag rid: 'SV-94081r1_rule'
  tag stig_id: 'AADC-CN-000955'
  tag gtitle: 'SRG-APP-000416'
  tag fix_id: 'F-86147r4_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
