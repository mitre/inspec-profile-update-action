control 'SV-218389' do
  title 'The audit system must be configured to audit failed attempts to access files and programs.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', 'Verify auditd is configured to audit failed file access attempts.
There must be an audit rule for each of the access syscalls logging all failed accesses (-F success=0) or
there must both an "-F exit=-EPERM" and "-F exit=-EACCES" for each access syscall.

Procedure:

# cat /etc/audit/audit.rules | grep -e "-a exit,always" | grep -e "-S truncate" | grep -e "-F success=0"
# cat /etc/audit/audit.rules | grep -e "-a exit,always" | grep -e "-S truncate" | grep -e "-F exit=-EPERM"
# cat /etc/audit/audit.rules | grep -e "-a exit,always" | grep -e "-S truncate" | grep -e "-F exit=-EACCES"

If an "-S truncate" audit rule with "-F success" does not exist and no separate rules containing "-F exit=-EPERM" and "-F exit=-EACCES" for "truncate" exist, then this is a finding.'
  desc 'fix', 'Edit the audit.rules file and add the following line(s) to enable auditing of failed attempts to access files and programs:

either:
-a exit,always -F arch=<ARCH> -S truncate -F success=0

or both:
-a exit,always -F arch=<ARCH> -S truncate -F exit=-EPERM
-a exit,always -F arch=<ARCH> -S truncate -F exit=-EACCES

Restart the auditd service.
# service auditd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19864r554504_chk'
  tag severity: 'medium'
  tag gid: 'V-218389'
  tag rid: 'SV-218389r603259_rule'
  tag stig_id: 'GEN002720-4'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag fix_id: 'F-19862r554505_fix'
  tag 'documentable'
  tag legacy: ['V-29238', 'SV-64257']
  tag cci: ['CCI-000366', 'CCI-000126']
  tag nist: ['CM-6 b', 'AU-2 c']
end
