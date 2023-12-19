control 'SV-207488' do
  title 'The VMM must implement NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The VMM must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', 'Verify the VMM implements NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to implement NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7745r365868_chk'
  tag severity: 'medium'
  tag gid: 'V-207488'
  tag rid: 'SV-207488r854662_rule'
  tag stig_id: 'SRG-OS-000396-VMM-001590'
  tag gtitle: 'SRG-OS-000396'
  tag fix_id: 'F-7745r365869_fix'
  tag 'documentable'
  tag legacy: ['SV-71537', 'V-57277']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
