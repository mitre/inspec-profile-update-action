control 'SV-218425' do
  title 'The audit system must be configured to audit the loading and unloading of dynamic kernel modules - /sbin/rmmod'
  desc 'Actions concerning dynamic kernel modules must be recorded as they are substantial events. Dynamic kernel modules can increase the attack surface of a system. A malicious kernel module can be used to substantially alter the functioning of a system, often with the purpose of hiding a compromise from the SA.'
  desc 'check', 'Determine if the /sbin/rmmod file is audited.

# cat /etc/audit/audit.rules | grep "/sbin/rmmod"

If the result does not start with "-w" and contain "-p x", this is a finding.'
  desc 'fix', 'The use of audit keys consistent with the provided example is encouraged to provide for uniform audit logs, however omitting the audit key or using an alternate audit key is not a finding.

Procedure:
Configure auditing of the /sbin/rmmod file.
Add the following to the "etc/audit/audit.rules" or "etc/audit.rules" file:

-w /sbin/rmmod -p x

Restart the auditd service.
# service auditd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19900r562438_chk'
  tag severity: 'medium'
  tag gid: 'V-218425'
  tag rid: 'SV-218425r603259_rule'
  tag stig_id: 'GEN002825-5'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag fix_id: 'F-19898r562439_fix'
  tag 'documentable'
  tag legacy: ['V-29288', 'SV-64425']
  tag cci: ['CCI-000126', 'CCI-000366']
  tag nist: ['AU-2 c', 'CM-6 b']
end
