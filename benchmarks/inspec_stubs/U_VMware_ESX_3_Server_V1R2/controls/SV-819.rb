control 'SV-819' do
  title 'The audit system must be configured to audit all discretionary access control permission modifications.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', 'Verify the system is configured to audit all discretionary access control permission modifications.  If the system does not audit any of these events, this is a finding.'
  desc 'fix', 'Configure the system to audit all discretionary access control permission modifications.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-28433r1_chk'
  tag severity: 'medium'
  tag gid: 'V-819'
  tag rid: 'SV-819r2_rule'
  tag stig_id: 'GEN002820'
  tag gtitle: 'GEN002820'
  tag fix_id: 'F-24550r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
