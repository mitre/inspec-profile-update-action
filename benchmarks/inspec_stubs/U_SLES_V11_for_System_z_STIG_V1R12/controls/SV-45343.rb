control 'SV-45343' do
  title 'The audit system must be configured to audit all discretionary access control permission modifications.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', %q(Check the system's audit configuration.

Procedure:
# cat /etc/audit/audit.rules | grep -e "-a exit,always" | grep -i " lremovexattr "
If "-S lremovexattr" is not in the result, this is a finding.)
  desc 'fix', 'The "-F arch=<ARCH>" restriction is required on dual-architecture systems (such as x86_64). On dual-architecture systems, two separate rules must exist - one for each architecture supported. Use the generic architectures "b32" and "b64" for specifying these rules.
On single architecture systems, the "-F arch=<ARCH>" restriction may be omitted, but if present must match either the architecture of the system or its corresponding generic architecture. The architecture of the system may be determined by running "uname -m". See the auditctl(8) manpage for additional details.
Any restrictions (such as with "-F") beyond those provided in the example rules are not in strict compliance with this requirement, and are a finding unless justified and documented appropriately.
The use of audit keys consistent with the provided example is encouraged to provide for uniform audit logs, however omitting the audit key or using an alternate audit key is not a finding.

Procedure:
Edit the audit.rules file and add the following lines to enable auditing of discretionary access control permissions modifications.
-a exit,always -F arch=<ARCH> -S lremovexattr

Restart the auditd service.
# rcauditd restart
        OR
# service auditd restart'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42693r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29275'
  tag rid: 'SV-45343r1_rule'
  tag stig_id: 'GEN002820-12'
  tag gtitle: 'GEN002820-12'
  tag fix_id: 'F-38739r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
