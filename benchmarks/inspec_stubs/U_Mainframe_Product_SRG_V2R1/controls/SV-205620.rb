control 'SV-205620' do
  title 'The Mainframe Product must implement NIST FIPS-validated cryptography to generate and validate cryptographic hashes in accordance with applicable federal laws, Executive orders, directives, policies, regulations, and standards.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', 'Examine installation and configuration settings. 

If the Mainframe Product does not implement FIPS 140 cryptography to generate and validate cryptographic hashes in accordance with applicable federal laws, Executive orders, directives, policies, regulations, and standards, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product settings to implement FIPS 140 cryptography to generate and validate cryptographic hashes in accordance with applicable federal laws, Executive orders, directives, policies, regulations, and standards.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5886r300087_chk'
  tag severity: 'medium'
  tag gid: 'V-205620'
  tag rid: 'SV-205620r851366_rule'
  tag stig_id: 'SRG-APP-000514-MFP-000272'
  tag gtitle: 'SRG-APP-000514'
  tag fix_id: 'F-5886r300088_fix'
  tag 'documentable'
  tag legacy: ['SV-82927', 'V-68437']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
