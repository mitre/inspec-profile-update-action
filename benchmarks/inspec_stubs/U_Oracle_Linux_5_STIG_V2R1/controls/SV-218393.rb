control 'SV-218393' do
  title 'The audit system must be configured to audit file deletions.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', 'Check the system audit configuration to determine if file and directory deletions are audited.

# cat /etc/audit/audit.rules | grep -e "-a exit,always" | grep -i "rmdir"

If no results are returned, or the results do not contain "-S rmdir", this is a finding.'
  desc 'fix', 'The "-F arch=<ARCH>" restriction is required on dual-architecture systems (such as x86_64).  On dual-architecture systems, two separate rules must exist - one for each architecture supported.  Use the generic architectures "b32" and "b64" for specifying these rules.  On single architecture systems, the "-F arch=<ARCH>" restriction may be omitted, but if present must match either the architecture of the system or its corresponding generic architecture.  The architecture of the system may be determined by running "uname -m".  See the auditctl(8) manpage for additional details.

Any restrictions (such as with "-F") beyond those provided in the example rules are not in strict compliance with this requirement and are a finding unless justified and documented appropriately.

The use of audit keys consistent with the provided example is encouraged to provide for uniform audit logs, however omitting the audit key or using an alternate audit key is not a finding.

Procedure:

Edit the /etc/audit/audit.rules file, and add one or more the lines (subject to the dual-architecture discussion above) to enable auditing of deletions:

-a exit,always -F arch=<ARCH> -S rmdir

Restart the auditd service:

# service auditd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19868r554516_chk'
  tag severity: 'medium'
  tag gid: 'V-218393'
  tag rid: 'SV-218393r603259_rule'
  tag stig_id: 'GEN002740-2'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag fix_id: 'F-19866r554517_fix'
  tag 'documentable'
  tag legacy: ['V-29240', 'SV-64265']
  tag cci: ['CCI-000366', 'CCI-000126']
  tag nist: ['CM-6 b', 'AU-2 c']
end
