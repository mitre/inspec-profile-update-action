control 'SV-45552' do
  title 'The audit system must be configured to audit the loading and unloading of dynamic kernel modules - /sbin/rmmod'
  desc 'Actions concerning dynamic kernel modules must be recorded as they are substantial events. Dynamic kernel modules can increase the attack surface of a system. A malicious kernel module can be used to substantially alter the functioning of a system, often with the purpose of hiding a compromise from the SA.'
  desc 'check', 'Determine if the /sbin/rmmod file is audited.

# cat /etc/audit/audit.rules | grep "/sbin/rmmod"
If the result does not start with "-w" and contain "-p x", this is a finding.'
  desc 'fix', 'The "-F arch=<ARCH>" restriction is required on dual-architecture systems (such as x86_64). On dual-architecture systems, two separate rules must exist - one for each architecture supported. Use the generic architectures "b32" and "b64" for specifying these rules.
On single architecture systems, the "-F arch=<ARCH>" restriction may be omitted, but if present must match either the architecture of the system or its corresponding generic architecture. The architecture of the system may be determined by running "uname -m". See the auditctl(8) manpage for additional details.
Any restrictions (such as with "-F") beyond those provided in the example rules are not in strict compliance with this requirement, and are a finding unless justified and documented appropriately.
The use of audit keys consistent with the provided example is encouraged to provide for uniform audit logs, however omitting the audit key or using an alternate audit key is not a finding.

Procedure:
Configure auditing of the /sbin/rmmod file.
Add the following to the "/etc/audit/audit.rules" file:

-w /sbin/rmmod -p x

Restart the auditd service.
# rcauditd restart
        OR
# service auditd restart'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42901r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29288'
  tag rid: 'SV-45552r1_rule'
  tag stig_id: 'GEN002825-5'
  tag gtitle: 'GEN002825-5'
  tag fix_id: 'F-38949r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
