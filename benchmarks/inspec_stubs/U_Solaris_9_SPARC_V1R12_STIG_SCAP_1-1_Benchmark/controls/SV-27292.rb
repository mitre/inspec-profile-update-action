control 'SV-27292' do
  title 'The audit system must be configured to audit file deletions.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'fix', 'Edit /etc/security/audit_control and add the fd to the flags list.
Load the new audit configuration.
# auditconfig -conf'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-815'
  tag rid: 'SV-27292r1_rule'
  tag stig_id: 'GEN002740'
  tag gtitle: 'GEN002740'
  tag fix_id: 'F-24528r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-2, ECAR-1, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
