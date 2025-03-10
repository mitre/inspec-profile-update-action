control 'SV-218421' do
  title 'The audit system must be configured to audit the loading and unloading of dynamic kernel modules.'
  desc 'Actions concerning dynamic kernel modules must be recorded as they are substantial events.  Dynamic kernel modules can increase the attack surface of a system.  A malicious kernel module can be used to substantially alter the functioning of a system, often with the purpose of hiding a compromise from the SA.'
  desc 'check', 'Determine if the init_module syscall is audited.

# cat /etc/audit/audit.rules | grep -e "-a exit,always" | grep -i "init_module"

If the result does not contain "-S init_module", this is a finding.'
  desc 'fix', 'The "-F arch=<ARCH>" restriction is required on dual-architecture systems (such as x86_64). On dual-architecture systems, two separate rules must exist - one for each architecture supported. Use the generic architectures "b32" and "b64" for specifying these rules.

On single architecture systems, the "-F arch=<ARCH>" restriction may be omitted, but if present must match either the architecture of the system or its corresponding generic architecture. The architecture of the system may be determined by running "uname -m". See the auditctl(8) manpage for additional details.

Any restrictions (such as with "-F") beyond those provided in the example rules are not in strict compliance with this requirement, and are a finding unless justified and documented appropriately.

The use of audit keys consistent with the provided example is encouraged to provide for uniform audit logs, however omitting the audit key or using an alternate audit key is not a finding.

Procedure:
Configure auditing of the init_module syscalls.
Add the following to the "etc/audit/audit.rules" or "etc/audit.rules" file:

-a exit,always -S init_module

Restart the auditd service.
# service auditd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19896r569122_chk'
  tag severity: 'medium'
  tag gid: 'V-218421'
  tag rid: 'SV-218421r603259_rule'
  tag stig_id: 'GEN002825'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag fix_id: 'F-19894r569123_fix'
  tag 'documentable'
  tag legacy: ['V-22383', 'SV-64505']
  tag cci: ['CCI-000126', 'CCI-000366']
  tag nist: ['AU-2 c', 'CM-6 b']
end
