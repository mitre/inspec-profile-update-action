control 'SV-35269' do
  title 'Auditing must be implemented.'
  desc 'Without auditing, individual system accesses cannot be tracked and malicious activity cannot be detected and traced back to an individual account.'
  desc 'check', 'Determine if auditing is enabled.
# audsys

If the audit service is not running, this is a finding.'
  desc 'fix', 'In order to turn auditing on, the system must first be in Trusted Mode. Next, turn on the auditing system. The system will use existing current and next audit trails (if configured).
# sam

Then: 

Auditing and Security -> Audited Events -> Actions -> Turn Auditing On.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-35101r1_chk'
  tag severity: 'medium'
  tag gid: 'V-811'
  tag rid: 'SV-35269r1_rule'
  tag stig_id: 'GEN002660'
  tag gtitle: 'GEN002660'
  tag fix_id: 'F-30370r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-2, ECAR-1, ECAR-3'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
