control 'SV-38476' do
  title 'Auditing must be implemented.'
  desc 'Without auditing, individual system accesses cannot be tracked and malicious activity cannot be detected and traced back to an individual account.'
  desc 'check', 'Determine if auditing is enabled.
# audsys

If the audit service is not running, this is a finding.'
  desc 'fix', 'Turn on the auditing system. The system will use existing current and next audit trails (if configured).
# audsys -n 

Alternatively, use the HP SMH to configure and enable auditing on the system.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36409r1_chk'
  tag severity: 'medium'
  tag gid: 'V-811'
  tag rid: 'SV-38476r1_rule'
  tag stig_id: 'GEN002660'
  tag gtitle: 'GEN002660'
  tag fix_id: 'F-31747r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
