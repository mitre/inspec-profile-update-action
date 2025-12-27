control 'SV-218402' do
  title 'The audit system must be configured to audit all administrative, privileged, and security actions.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', 'Check the auditing configuration of the system.

Procedure:
# cat /etc/audit/audit.rules | grep -e "-a exit,always" | grep -i "stime"

# cat /etc/audit/audit.rules | grep -e "-a exit,always" | grep -i "settimeofday"

If the result does not contain "-S stime" or "-S settimeofday ", this is a finding.

The "stime" keyword is only required on systems using an i386 architecture.'
  desc 'fix', 'The "-F arch=<ARCH>"restriction is required on dual-architecture systems (such as x86_64). On dual-architecture systems, two separate rules must exist - one for each architecture supported. Use the generic architectures "b32" and "b64" for specifying these rules.
On single architecture systems, the "-F arch=<ARCH>"restriction may be omitted, but if present must match either the architecture of the system or its corresponding generic architecture. The architecture of the system may be determined by running "uname -m". See the auditctl(8) manpage for additional details.
Any restrictions (such as with "-F") beyond those provided in the example rules are not in strict compliance with this requirement, and are a finding unless justified and documented appropriately.
The use of audit keys consistent with the provided example is encouraged to provide for uniform audit logs, however omitting the audit key or using an alternate audit key is not a finding.
Procedure:
Add the following lines to the audit.rules file to enable auditing of administrative, privileged, and security actions:

-a exit,always -F arch=<ARCH> -S stime (only used for systems using an i386 architecture)
-a exit,always -F arch=<ARCH> -S settimeofday (used on all non-i386 architectures such as b64 and x86_64)

Restart the auditd service.
# service auditd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19877r569107_chk'
  tag severity: 'medium'
  tag gid: 'V-218402'
  tag rid: 'SV-218402r603259_rule'
  tag stig_id: 'GEN002760-5'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag fix_id: 'F-19875r569108_fix'
  tag 'documentable'
  tag legacy: ['V-29244', 'SV-64491']
  tag cci: ['CCI-000169', 'CCI-000347']
  tag nist: ['AU-12 a', 'CM-5 (1)']
end
