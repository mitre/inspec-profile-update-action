control 'SV-218399' do
  title 'The audit system must be configured to audit all administrative, privileged, and security actions.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', 'Check the auditing configuration of the system.

Procedure:

# cat /etc/audit/audit.rules | grep -i "audit.rules"

If no results are returned, or the line does not start with "-w", this is a finding.'
  desc 'fix', 'The use of audit keys consistent with the provided example is encouraged to provide for uniform audit logs, however omitting the audit key or using an alternate audit key is not a finding.

Procedure:
Add the following lines to the audit.rules file to enable auditing of administrative, privileged, and security actions:

-w /etc/audit/audit.rules

Restart the auditd service.
# service auditd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19874r569098_chk'
  tag severity: 'medium'
  tag gid: 'V-218399'
  tag rid: 'SV-218399r603259_rule'
  tag stig_id: 'GEN002760-2'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag fix_id: 'F-19872r569099_fix'
  tag 'documentable'
  tag legacy: ['V-29241', 'SV-64471']
  tag cci: ['CCI-000347', 'CCI-000169']
  tag nist: ['CM-5 (1)', 'AU-12 a']
end
