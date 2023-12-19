control 'SV-38482' do
  title 'The audit system must be configured to audit login, logout, and session initiation.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'fix', 'Edit /etc/rc.config.d/auditing and add -e login to the end of the AUDEVENT_ARGS1 parameter.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-818'
  tag rid: 'SV-38482r1_rule'
  tag stig_id: 'GEN002800'
  tag gtitle: 'GEN002800'
  tag fix_id: 'F-31768r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-3, ECAR-2, ECAR-1'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
