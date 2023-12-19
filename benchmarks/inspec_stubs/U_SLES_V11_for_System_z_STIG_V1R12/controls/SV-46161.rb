control 'SV-46161' do
  title 'The audit system must be configured to audit all administrative, privileged, and security actions.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', 'Check the auditing configuration of the system.

Procedure:
# cat /etc/audit/audit.rules | grep -i "auditd.conf"
If no results are returned, or the line does not start with "-w", this is a finding.'
  desc 'fix', 'The "-F arch=<ARCH>"restriction is required on dual-architecture systems (such as x86_64). On dual-architecture systems, two separate rules must exist - one for each architecture supported. Use the generic architectures "b32" and "b64" for specifying these rules.
On single architecture systems, the "-F arch=<ARCH>"restriction may be omitted, but if present must match either the architecture of the system or its corresponding generic architecture. The architecture of the system may be determined by running "uname -m". See the auditctl(8) manpage for additional details.
Any restrictions (such as with "-F") beyond those provided in the example rules are not in strict compliance with this requirement, and are a finding unless justified and documented appropriately.
The use of audit keys consistent with the provided example is encouraged to provide for uniform audit logs, however omitting the audit key or using an alternate audit key is not a finding.
Procedure:
Add the following lines to the audit.rules file to enable auditing of administrative, privileged, and security actions:

-w /etc/audit/auditd.conf
Restart the auditd service.
# rcauditd restart
        OR
# service auditd restart'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43419r1_chk'
  tag severity: 'medium'
  tag gid: 'V-816'
  tag rid: 'SV-46161r1_rule'
  tag stig_id: 'GEN002760'
  tag gtitle: 'GEN002760'
  tag fix_id: 'F-39497r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000347']
  tag nist: ['CM-5 (1)']
end
