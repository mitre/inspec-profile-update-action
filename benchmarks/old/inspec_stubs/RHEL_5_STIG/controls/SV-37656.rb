control 'SV-37656' do
  title 'The audit system must be configured to audit file deletions.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'fix', 'Edit the audit.rules file and add the following line to enable auditing of deletions:
-a exit,always -S rmdir 

Restart the auditd service.
# service auditd restart'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-29240'
  tag rid: 'SV-37656r1_rule'
  tag stig_id: 'GEN002740-2'
  tag gtitle: 'GEN002740-2'
  tag fix_id: 'F-31683r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
