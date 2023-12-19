control 'SV-82925' do
  title 'The Mainframe Product must implement NIST FIPS-validated cryptography to provision digital signatures in accordance with applicable federal laws, Executive orders, directives, policies, regulations, and standards.'
  desc "Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

For detailed information, refer to NIST FIPS Publication 140-2, Security Requirements For Cryptographic Modules. Note that the product's cryptographic modules must be validated and certified by NIST as FIPS compliant."
  desc 'check', 'Examine installation and configuration settings. 

If the Mainframe Product does not implement FIPS 140 cryptography to provision digital signatures in accordance with applicable federal laws, Executive orders, directives, policies, regulations, and standards, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product settings to implement FIPS 140 cryptography to provision digital signatures in accordance with applicable federal laws, Executive orders, directives, policies, regulations, and standards.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68967r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68435'
  tag rid: 'SV-82925r1_rule'
  tag stig_id: 'SRG-APP-000514-MFP-000270'
  tag gtitle: 'SRG-APP-000514-MFP-000270'
  tag fix_id: 'F-74551r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
