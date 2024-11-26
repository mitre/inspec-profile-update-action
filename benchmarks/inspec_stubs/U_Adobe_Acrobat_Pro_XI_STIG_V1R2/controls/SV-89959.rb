control 'SV-89959' do
  title 'Adobe Acrobat Pro XI FIPS mode must be enabled.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

'
  desc 'check', 'Verify the following registry configuration:

Note: The Key Name "bFIPSMode" is not created by default in the Acrobat Pro XI install and must be created.

Using the Registry Editor, navigate to the following: HKEY_CURRENT_USER\\Software\\Adobe\\Adobe Acrobat\\11.0\\AVGeneral

Value Name: bFIPSMode
Type: REG_DWORD
Value: 1

If the value for bFIPSMode is not set to “1” and Type is not configured to REG_DWORD or does not exist, this is a finding.'
  desc 'fix', 'Configure the following registry value:

Note: The Key Name "bFIPSMode" is not created by default in the Acrobat Pro XI install and must be created.

Registry Hive:
HKEY_CURRENT_USER
Registry Path:
\\Software\\Adobe\\Adobe Acrobat\\11.0\\AVGeneral

Value Name: bFIPSMode
Type: REG_DWORD
Value: 1'
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Pro XI'
  tag check_id: 'C-75063r2_chk'
  tag severity: 'medium'
  tag gid: 'V-75279'
  tag rid: 'SV-89959r1_rule'
  tag stig_id: 'ADBP-XI-000955'
  tag gtitle: 'SRG-APP-000416'
  tag fix_id: 'F-81895r3_fix'
  tag satisfies: ['SRG-APP-000416', 'SRG-APP-000514']
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
