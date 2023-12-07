control 'SV-37664' do
  title 'The audit system must be configured to audit all administrative, privileged, and security actions.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'fix', 'The "-F arch=<ARCH>"restriction is required on dual-architecture systems (such as x86_64). On dual-architecture systems, two separate rules must exist - one for each architecture supported. Use the generic architectures "b32" and "b64" for specifying these rules.
On single architecture systems, the "-F arch=<ARCH>"restriction may be omitted, but if present must match either the architecture of the system or its corresponding generic architecture. The architecture of the system may be determined by running "uname -m". See the auditctl(8) manpage for additional details.
Any restrictions (such as with "-F") beyond those provided in the example rules are not in strict compliance with this requirement, and are a finding unless justified and documented appropriately.
The use of audit keys consistent with the provided example is encouraged to provide for uniform audit logs, however omitting the audit key or using an alternate audit key is not a finding.
Procedure:
A Real Time Operating System (RTOS) provides specialized system scheduling which causes an inordinate number of messages to be produced when the sched_setparam and set_setscheduler are audited. This not only may degrade the system speed to an unusable level but obscures any forensic information which may otherwise have been useful.
Unless the operating system is a Red Hat 5 based RTOS (including MRG and AS5300) the following should also be present in /etc/audit/audit.rules

-a exit,always -F arch=<ARCH> -S sched_setparam

Restart the auditd service.
# service auditd restart'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-29248'
  tag rid: 'SV-37664r1_rule'
  tag stig_id: 'GEN002760-9'
  tag gtitle: 'GEN002760-9'
  tag fix_id: 'F-31690r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000347']
  tag nist: ['CM-5 (1)']
end
