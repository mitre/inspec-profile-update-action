control 'SV-38645' do
  title 'The audit system must be configured to audit failed attempts to access files and programs.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', 'Verify auditd is configured to audit failed file access attempts.

There must be an audit rule for each of the access syscalls logging all failed accesses (-F success=0) or there must both an "-F exit=-EPERM" and "-F exit=-EACCES" for each access syscall.

Procedure:
# cat /etc/audit/audit.rules | grep -e "-a exit,always" | grep -e "-S creat" | grep -e "-F success=0"
# cat /etc/audit/audit.rules | grep -e "-a exit,always" | grep -e "-S creat" | grep -e "-F exit=-EPERM"
# cat /etc/audit/audit.rules | grep -e "-a exit,always" | grep -e "-S creat" | grep -e "-F exit=-EACCES"

If an "-S creat" audit rule with "-F success" does not exist and no separate rules containing "-F exit=-EPERM" and "-F exit=-EACCES" for "creat" exist, then this is a finding.'
  desc 'fix', 'Edit the audit.rules file and add the following line(s) to enable auditing of failed attempts to access files and programs:

either:
-a exit,always -F arch=<ARCH> -S creat -F success=0

or both:
-a exit,always -F arch=<ARCH> -S creat -F exit=-EPERM
-a exit,always -F arch=<ARCH> -S creat -F exit=-EACCES

Restart the auditd service.
# service auditd restart'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37782r2_chk'
  tag severity: 'medium'
  tag gid: 'V-814'
  tag rid: 'SV-38645r1_rule'
  tag stig_id: 'GEN002720'
  tag gtitle: 'GEN002720'
  tag fix_id: 'F-33035r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
