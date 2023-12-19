control 'SV-38480' do
  title 'The audit system must be configured to audit file deletions.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'fix', 'Edit /etc/rc.config.d/auditing and add -e delete to the end of the AUDEVENT_ARGS1 parameter.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-815'
  tag rid: 'SV-38480r1_rule'
  tag stig_id: 'GEN002740'
  tag gtitle: 'GEN002740'
  tag fix_id: 'F-31766r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
