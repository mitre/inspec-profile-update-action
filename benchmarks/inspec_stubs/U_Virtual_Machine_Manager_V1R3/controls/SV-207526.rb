control 'SV-207526' do
  title 'The VMM must implement NIST FIPS-validated cryptography for the following: to provision digital signatures; to generate cryptographic hashes; and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The VMM must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', 'Verify the VMM implements NIST FIPS-validated cryptography for the following: to provision digital signatures; to generate cryptographic hashes; and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to implement NIST FIPS-validated cryptography for the following: to provision digital signatures; to generate cryptographic hashes; and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7783r878144_chk'
  tag severity: 'medium'
  tag gid: 'V-207526'
  tag rid: 'SV-207526r878146_rule'
  tag stig_id: 'SRG-OS-000478-VMM-001980'
  tag gtitle: 'SRG-OS-000478'
  tag fix_id: 'F-7783r878145_fix'
  tag 'documentable'
  tag legacy: ['V-57353', 'SV-71613']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
