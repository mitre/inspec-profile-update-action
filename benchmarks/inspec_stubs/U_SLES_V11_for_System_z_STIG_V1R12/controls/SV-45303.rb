control 'SV-45303' do
  title 'The audit system must be configured to audit file deletions.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', 'Check the system audit configuration to determine if file and directory deletions are audited.

# cat /etc/audit/audit.rules | grep -e "-a exit,always" | grep -i "unlink"
If no results are returned, or the results do not contain "-S unlink", this is a finding.'
  desc 'fix', 'Edit the audit.rules file and add the following line to enable auditing of deletions:
-a exit,always -S unlink

Restart the auditd service.
# rcauditd restart
          OR# service auditd restart'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42651r1_chk'
  tag severity: 'medium'
  tag gid: 'V-815'
  tag rid: 'SV-45303r1_rule'
  tag stig_id: 'GEN002740'
  tag gtitle: 'GEN002740'
  tag fix_id: 'F-38699r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
