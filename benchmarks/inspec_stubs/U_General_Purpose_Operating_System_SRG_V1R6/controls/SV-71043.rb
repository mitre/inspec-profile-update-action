control 'SV-71043' do
  title 'The operating system must implement NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', 'Verify the operating system implements NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to implement NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57353r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56783'
  tag rid: 'SV-71043r1_rule'
  tag stig_id: 'SRG-OS-000396-GPOS-00176'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-61679r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
