control 'SV-37738' do
  title 'The audit system must be configured to audit the loading and unloading of dynamic kernel modules -/sbin/modprobe.'
  desc 'Actions concerning dynamic kernel modules must be recorded as they are substantial events. Dynamic kernel modules can increase the attack surface of a system. A malicious kernel module can be used to substantially alter the functioning of a system, often with the purpose of hiding a compromise from the SA.'
  desc 'fix', 'The use of audit keys consistent with the provided example is encouraged to provide for uniform audit logs, however omitting the audit key or using an alternate audit key is not a finding.
Procedure:
-w /sbin/modprobe -p x

Restart the auditd service.
# service auditd restart'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-29286'
  tag rid: 'SV-37738r2_rule'
  tag stig_id: 'GEN002825-4'
  tag gtitle: 'GEN002825-4'
  tag fix_id: 'F-32199r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
