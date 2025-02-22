control 'SV-37612' do
  title 'The audit system must be configured to audit failed attempts to access files and programs.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', 'Check that auditd is configured to audit failed file access attempts.
There must be an audit rule for each of the access syscalls that logs all failed accesses (-F success=0) or there must both an "-F exit=-EPERM" and "-F exit=-EACCES" for each access syscall.

Procedure:
# cat /etc/audit/audit.rules | grep -e "-a exit,always" | grep -e "-S open" | grep -e "-F success=0"
# cat /etc/audit/audit.rules | grep -e "-a exit,always" | grep -e "-S open" | grep -e "-F exit=-EPERM"
# cat /etc/audit/audit.rules | grep -e "-a exit,always" | grep -e "-S open" | grep -e "-F exit=-EACCES"

If an "-S open" audit rule with "-F success" does not exist and no separate rules containing "-F exit=-EPERM" and "-F exit=-EACCES" for "open" exist, then this is a finding.'
  desc 'fix', 'Edit the audit.rules file and add the following line(s) to enable auditing of failed attempts to access files and programs:

either:
-a exit,always -F arch=<ARCH> -S open -F success=0

or both:
-a exit,always -F arch=<ARCH> -S open -F exit=-EPERM
-a exit,always -F arch=<ARCH> -S open -F exit=-EACCES

Restart the auditd service.
# service auditd restart'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36810r2_chk'
  tag severity: 'medium'
  tag gid: 'V-29236'
  tag rid: 'SV-37612r2_rule'
  tag stig_id: 'GEN002720-2'
  tag gtitle: 'GEN002720-2'
  tag fix_id: 'F-31649r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
