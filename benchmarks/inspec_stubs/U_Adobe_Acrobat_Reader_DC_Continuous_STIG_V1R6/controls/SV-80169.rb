control 'SV-80169' do
  title 'Adobe Reader DC must enable FIPS mode.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', 'Verify the following registry configuration:

Note: The Key Names "bFIPSMode" is not created by default in the Adobe Reader DC install and must be created.

Utilizing the Registry Editor, navigate to the following: HKEY_CURRENT_USER\\Software\\Adobe\\Acrobat Reader\\DC\\AVGeneral

Value Name: bFIPSMode 
Type: REG_DWORD
Value: 1

If the value for bFIPSMode is not set to “1” and Type configured to REG_DWORD does not exist, then this is a finding.'
  desc 'fix', 'Configure the following registry value:

Note: The Key Names "bFIPSMode" is not created by default in the Adobe Reader DC install and must be created.

Registry Hive: HKEY_CURRENT_USER
Registry Path: \\Software\\Adobe\\Acrobat Reader\\DC\\AVGeneral

Value Name: bFIPSMode 
Type: REG_DWORD
Value: 1'
  impact 0.5
  ref 'DPMS Target Adobe Acrobat Reader DC Continuous'
  tag check_id: 'C-66253r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65679'
  tag rid: 'SV-80169r1_rule'
  tag stig_id: 'ARDC-CN-000345'
  tag gtitle: 'SRG-APP-000514'
  tag fix_id: 'F-71639r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
