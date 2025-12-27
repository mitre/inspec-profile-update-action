control 'SV-203776' do
  title 'The operating system must implement NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', 'Verify the operating system implements NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to implement NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  impact 0.7
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3901r877032_chk'
  tag severity: 'high'
  tag gid: 'V-203776'
  tag rid: 'SV-203776r877466_rule'
  tag stig_id: 'SRG-OS-000478-GPOS-00223'
  tag gtitle: 'SRG-OS-000478'
  tag fix_id: 'F-3901r877031_fix'
  tag 'documentable'
  tag legacy: ['SV-70861', 'V-56601']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
