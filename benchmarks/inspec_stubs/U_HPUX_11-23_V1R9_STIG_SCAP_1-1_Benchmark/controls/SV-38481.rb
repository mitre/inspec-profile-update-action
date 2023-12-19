control 'SV-38481' do
  title 'The audit system must be configured to audit all administrative, privileged, and security actions.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'fix', 'Edit /etc/rc.config.d/auditing and add -e admin and -e removable to the end of the AUDEVENT_ARGS1 parameter.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-816'
  tag rid: 'SV-38481r1_rule'
  tag stig_id: 'GEN002760'
  tag gtitle: 'GEN002760'
  tag fix_id: 'F-31767r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000347']
  tag nist: ['CM-5 (1)']
end
