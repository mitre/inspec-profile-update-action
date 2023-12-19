control 'SV-218424' do
  title 'The audit system must be configured to audit the loading and unloading of dynamic kernel modules -/sbin/modprobe.'
  desc 'Actions concerning dynamic kernel modules must be recorded as they are substantial events. Dynamic kernel modules can increase the attack surface of a system. A malicious kernel module can be used to substantially alter the functioning of a system, often with the purpose of hiding a compromise from the SA.'
  desc 'check', 'Determine if the /sbin/modprobe file is audited.

# cat /etc/audit/audit.rules | grep "/sbin/modprobe"

If the result does not start with "-w" and contain "-p x", this is a finding.'
  desc 'fix', 'The use of audit keys consistent with the provided example is encouraged to provide for uniform audit logs, however omitting the audit key or using an alternate audit key is not a finding.
Procedure:
-w /sbin/modprobe -p x

Restart the auditd service.
# service auditd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19899r562435_chk'
  tag severity: 'medium'
  tag gid: 'V-218424'
  tag rid: 'SV-218424r603259_rule'
  tag stig_id: 'GEN002825-4'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag fix_id: 'F-19897r562436_fix'
  tag 'documentable'
  tag legacy: ['V-29286', 'SV-64429']
  tag cci: ['CCI-000366', 'CCI-000126']
  tag nist: ['CM-6 b', 'AU-2 c']
end
