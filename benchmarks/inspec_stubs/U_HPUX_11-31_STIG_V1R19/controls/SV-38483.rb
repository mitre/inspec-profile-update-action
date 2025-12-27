control 'SV-38483' do
  title 'The audit system must be configured to audit all discretionary access control permission modifications.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', "Check the system's audit configuration. The term moddac is code for MODify Dicscretionary Access Control (i.e., chown, chmod, etc.).
# grep -i audevent_args1 /etc/rc.config.d/auditing | grep moddac

If no results are returned, this is a finding."
  desc 'fix', 'Edit /etc/rc.config.d/auditing and add -e moddac to the end of the AUDEVENT_ARGS1 parameter.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36430r1_chk'
  tag severity: 'medium'
  tag gid: 'V-819'
  tag rid: 'SV-38483r1_rule'
  tag stig_id: 'GEN002820'
  tag gtitle: 'GEN002820'
  tag fix_id: 'F-31769r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
