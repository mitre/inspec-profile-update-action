control 'SV-206639' do
  title 'The DBMS must implement NIST FIPS 140-2 or 140-3 validated cryptographic modules to provision digital signatures.'
  desc "Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

For detailed information, refer to NIST FIPS Publication 140-3, Security Requirements For Cryptographic Modules. Note that the product's cryptographic modules must be validated and certified by NIST as FIPS-compliant."
  desc 'check', 'If the DBMS does not employ NIST FIPS 140-2 or 140-3 validated cryptographic modules to provision digital signatures, this is a finding.'
  desc 'fix', 'Implement NIST FIPS 140-2 or 140-3 validated cryptographic modules to provision digital signatures.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6899r836862_chk'
  tag severity: 'medium'
  tag gid: 'V-206639'
  tag rid: 'SV-206639r836864_rule'
  tag stig_id: 'SRG-APP-000514-DB-000381'
  tag gtitle: 'SRG-APP-000514'
  tag fix_id: 'F-6899r836863_fix'
  tag 'documentable'
  tag legacy: ['SV-72589', 'V-58159']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
