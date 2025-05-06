control 'SV-29676' do
  title 'The audit system must be configured to audit account disabling.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'fix', 'Edit /etc/rc.config.d/auditing and add -e admin to the end of the AUDEVENT_ARGS1 parameter.'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'low'
  tag gid: 'V-22378'
  tag rid: 'SV-29676r1_rule'
  tag stig_id: 'GEN002752'
  tag gtitle: 'GEN002752'
  tag fix_id: 'F-31784r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAT-1'
  tag cci: ['CCI-001404']
  tag nist: ['AC-2 (4)']
end
