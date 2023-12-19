control 'SV-37668' do
  title 'The audit system must be configured to audit all discretionary access control permission modifications.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', %q(Check the system's audit configuration.

Procedure:
# cat /etc/audit/audit.rules | grep -e "-a exit,always" | grep -i "chown"

If "-S chown" is not in the result, this is a finding.

Additionally, the following rule is required in systems supporting the 32-bit syscall table (such as i686 and x86_64):

# cat /etc/audit/audit.rules | grep -e "-a exit,always" | grep -i "chown32"

If "-S chown32" is not in the result, this is a finding.)
  desc 'fix', 'The "-F arch=<ARCH>" restriction is required on dual-architecture systems (such as x86_64). On dual-architecture systems, two separate rules must exist - one for each architecture supported. Use the generic architectures "b32" and "b64" for specifying these rules.
On single architecture systems, the "-F arch=<ARCH>" restriction may be omitted, but if present must match either the architecture of the system or its corresponding generic architecture. The architecture of the system may be determined by running "uname -m". See the auditctl(8) manpage for additional details.
Any restrictions (such as with "-F") beyond those provided in the example rules are not in strict compliance with this requirement, and are a finding unless justified and documented appropriately.
The use of audit keys consistent with the provided example is encouraged to provide for uniform audit logs, however omitting the audit key or using an alternate audit key is not a finding.

Procedure:
Edit the audit.rules file and add the following lines to enable auditing of discretionary access control permissions modifications.
-a exit,always -F arch=<ARCH> -S chown

Additionally, the following rule is required in systems supporting the 32-bit syscall table (such as i686 and x86_64):
-a exit,always -F arch=<ARCH> -S chown32

Restart the auditd service.
# service auditd restart'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36857r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29252'
  tag rid: 'SV-37668r1_rule'
  tag stig_id: 'GEN002820-4'
  tag gtitle: 'GEN002820-4'
  tag fix_id: 'F-31710r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
