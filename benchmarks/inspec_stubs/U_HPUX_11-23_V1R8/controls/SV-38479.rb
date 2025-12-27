control 'SV-38479' do
  title 'The audit system must be configured to audit failed attempts to access files and programs.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', 'Check the system audit configuration to determine if failed attempts to access files and programs are audited.
# grep -i audevent_args1 /etc/rc.config.d/auditing | grep open

If no results are returned, this is a finding.'
  desc 'fix', 'Edit /etc/rc.config.d/auditing and add -e open to the end of the AUDEVENT_ARGS1 parameter.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36426r1_chk'
  tag severity: 'medium'
  tag gid: 'V-814'
  tag rid: 'SV-38479r1_rule'
  tag stig_id: 'GEN002720'
  tag gtitle: 'GEN002720'
  tag fix_id: 'F-31765r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-2, ECAR-1, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
