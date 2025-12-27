control 'SV-218398' do
  title 'The audit system must be configured to audit all administrative, privileged, and security actions.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', 'Check the auditing configuration of the system.

Procedure:
# cat /etc/audit/audit.rules | grep -e "-a exit,always" | grep -i "sched_setscheduler"

If the result does not contain "-S sched_setscheduler", this is a finding.'
  desc 'fix', 'The "-F arch=<ARCH>" restriction is required on dual-architecture systems (such as x86_64).  On dual-architecture systems, two separate rules must exist - one for each architecture supported.  Use the generic architectures "b32" and "b64" for specifying these rules.  On single architecture systems, the "-F arch=<ARCH>" restriction may be omitted, but if present must match either the architecture of the system or its corresponding generic architecture.  The architecture of the system may be determined by running "uname -m".  See the auditctl(8) manpage for additional details.

Any restrictions (such as with "-F") beyond those provided in the example rules are not in strict compliance with this requirement and are a finding unless justified and documented appropriately.

The use of audit keys consistent with the provided example is encouraged to provide for uniform audit logs, however omitting the audit key or using an alternate audit key is not a finding.

Procedure:

Edit the /etc/audit/audit.rules file, and add one or more the lines (subject to the dual-architecture discussion above) to enable auditing of operations that change operating system scheduling algorithms and parameters:

-a exit,always -F arch=<ARCH> -S sched_setscheduler

Restart the auditd service:

# service auditd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19873r569095_chk'
  tag severity: 'medium'
  tag gid: 'V-218398'
  tag rid: 'SV-218398r603259_rule'
  tag stig_id: 'GEN002760-10'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag fix_id: 'F-19871r569096_fix'
  tag 'documentable'
  tag legacy: ['V-29249', 'SV-64275']
  tag cci: ['CCI-000169', 'CCI-000347']
  tag nist: ['AU-12 a', 'CM-5 (1)']
end
