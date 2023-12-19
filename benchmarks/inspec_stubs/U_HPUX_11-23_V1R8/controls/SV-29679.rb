control 'SV-29679' do
  title 'The audit system must be configured to audit account termination.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', 'Check the auditing configuration of the system.

Procedure:
# grep -i audevent_args1 /etc/rc.config.d/auditing | grep admin

If no results are returned, the system is not configured to audit administrative actions, this is a finding.'
  desc 'fix', 'Edit /etc/rc.config.d/auditing and add -e admin to the end of the AUDEVENT_ARGS1 parameter.'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36446r1_chk'
  tag severity: 'low'
  tag gid: 'V-22382'
  tag rid: 'SV-29679r1_rule'
  tag stig_id: 'GEN002753'
  tag gtitle: 'GEN002753'
  tag fix_id: 'F-31785r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAT-1'
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end
