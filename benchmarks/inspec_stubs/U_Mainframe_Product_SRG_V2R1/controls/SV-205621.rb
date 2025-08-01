control 'SV-205621' do
  title 'The Mainframe Product must implement NIST FIPS-validated cryptography to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive orders, directives, policies, regulations, and standards.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', 'Examine installation and configuration settings. 

If the Mainframe Product does not implement FIPS 140 cryptography to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive orders, directives, policies, regulations, and standards, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product settings to implement FIPS 140 cryptography to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive orders, directives, policies, regulations, and standards.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5887r300090_chk'
  tag severity: 'medium'
  tag gid: 'V-205621'
  tag rid: 'SV-205621r864584_rule'
  tag stig_id: 'SRG-APP-000514-MFP-000274'
  tag gtitle: 'SRG-APP-000514'
  tag fix_id: 'F-5887r539607_fix'
  tag 'documentable'
  tag legacy: ['SV-82929', 'V-68439']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
