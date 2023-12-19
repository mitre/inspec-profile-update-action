control 'SV-45292' do
  title 'The audit system must be configured to audit failed attempts to access files and programs.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', 'Verify auditd is configured to audit failed file access attempts.
There must be an audit rule for each of the access syscalls logging all failed accesses (-F success=0) or
there must both an "-F exit=-EPERM" and "-F exit=-EACCES" for each access syscall.

Procedure:
# cat /etc/audit/audit.rules | grep -e "-a exit,always" | grep -e "-S ftruncate" | grep -e "-F success=0"
# cat /etc/audit/audit.rules | grep -e "-a exit,always" | grep -e "-S ftruncate" | grep -e "-F exit=-EPERM"
# cat /etc/audit/audit.rules | grep -e "-a exit,always" | grep -e "-S ftruncate" | grep -e "-F exit=-EACCES"
If an "-S ftruncate" audit rule with "-F success" does not exist and no separate rules containing "-F exit=-EPERM" and "-F exit=-EACCES" for "ftruncate" exist, then this is a finding.'
  desc 'fix', 'Edit the audit.rules file and add the following line(s) to enable auditing of failed attempts to access files and programs:

either:
-a exit,always -F arch=<ARCH> -S ftruncate -F success=0

or both:
-a exit,always -F arch=<ARCH> -S ftruncate -F exit=-EPERM
-a exit,always -F arch=<ARCH> -S ftruncate -F exit=-EACCES

Restart the auditd service.
# rcauditd restart
         OR
# service auditd restart'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42640r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29239'
  tag rid: 'SV-45292r1_rule'
  tag stig_id: 'GEN002720-5'
  tag gtitle: 'GEN002720-5'
  tag fix_id: 'F-38688r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
