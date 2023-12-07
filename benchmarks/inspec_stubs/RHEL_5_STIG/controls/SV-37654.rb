control 'SV-37654' do
  title 'The audit system must be configured to audit failed attempts to access files and programs.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'fix', 'Edit the audit.rules file and add the following line(s) to enable auditing of failed attempts to access files and programs:

either:
-a exit,always -F arch=<ARCH> -S truncate -F success=0

or both:
-a exit,always -F arch=<ARCH> -S truncate -F exit=-EPERM
-a exit,always -F arch=<ARCH> -S truncate -F exit=-EACCES

Restart the auditd service.
# service auditd restart'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-29238'
  tag rid: 'SV-37654r2_rule'
  tag stig_id: 'GEN002720-4'
  tag gtitle: 'GEN002720-4'
  tag fix_id: 'F-31681r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
