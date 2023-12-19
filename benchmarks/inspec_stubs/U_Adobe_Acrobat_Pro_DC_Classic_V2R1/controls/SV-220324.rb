control 'SV-220324' do
  title 'Adobe Acrobat Pro DC Classic FIPS mode must be enabled.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', %q(Verify the following registry configuration:

Using the Registry Editor, navigate to the following: HKEY_CURRENT_USER\Software\Adobe\Adobe Acrobat\2015\AVGeneral

Value Name: bFIPSMode
Type: REG_DWORD
Value: 1

If the value for bFIPSMode is not set to "1" and Type is not configured to REG_DWORD or does not exist, this is a finding.

Admin Template path: User Configuration > Administrative Templates > Adobe Acrobat Pro DC Classic > Preferences > 'Enable FIPS' must be set to 'Enabled'.

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  desc 'fix', %q(Configure the following registry value:

Registry Hive:
HKEY_CURRENT_USER
Registry Path:
\Software\Adobe\Adobe Acrobat\2015\AVGeneral

Value Name: bFIPSMode
Type: REG_DWORD
Value: 1
Configure the policy value for User Configuration > Administrative Templates > Adobe Acrobat Pro DC Classic > Preferences > 'Enable FIPS' to 'Enabled'.

This policy setting requires the installation of the AcrobatProDCClassic custom templates included with the STIG package. "AcrobatProDCClassic.admx" and "AcrobatProDCClassic.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.)
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Professional DC Classic Track'
  tag check_id: 'C-22039r478167_chk'
  tag severity: 'medium'
  tag gid: 'V-220324'
  tag rid: 'SV-220324r557504_rule'
  tag stig_id: 'AADC-CL-000955'
  tag gtitle: 'SRG-APP-000416'
  tag fix_id: 'F-22028r478168_fix'
  tag 'documentable'
  tag legacy: ['V-80127', 'SV-94831']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
