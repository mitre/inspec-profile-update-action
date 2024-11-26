control 'SV-37734' do
  title 'The audit system must be configured to audit the loading and unloading of dynamic kernel modules - /sbin/insmod.'
  desc 'Actions concerning dynamic kernel modules must be recorded as they are substantial events. Dynamic kernel modules can increase the attack surface of a system. A malicious kernel module can be used to substantially alter the functioning of a system, often with the purpose of hiding a compromise from the SA.'
  desc 'check', 'Determine if /sbin/insmod is audited.

# cat /etc/audit/audit.rules | grep "/sbin/insmod"

If the result does not start with "-w" and contain "-p x", this is a finding.'
  desc 'fix', 'The use of audit keys consistent with the provided example is encouraged to provide for uniform audit logs, however omitting the audit key or using an alternate audit key is not a finding.
Procedure:

Configure auditing of the /sbin/insmod, files.
Add the following to the "etc/audit/audit.rules" or "etc/audit.rules" file:
-w /sbin/insmod -p x

Restart the auditd service.
# service auditd restart'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36932r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29284'
  tag rid: 'SV-37734r2_rule'
  tag stig_id: 'GEN002825-3'
  tag gtitle: 'GEN002825-3'
  tag fix_id: 'F-32197r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
