control 'SV-68677' do
  title 'The ALG must off-load audit records onto a centralized log server.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the ALG off-loads audit records onto a centralized log server.

If the ALG does not off-load audit records onto a centralized log server, this is a finding.'
  desc 'fix', 'Configure the ALG to off-load audit records onto a centralized log server.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55047r2_chk'
  tag severity: 'medium'
  tag gid: 'V-54431'
  tag rid: 'SV-68677r1_rule'
  tag stig_id: 'SRG-NET-000334-ALG-000050'
  tag gtitle: 'SRG-NET-000334-ALG-000050'
  tag fix_id: 'F-59285r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
