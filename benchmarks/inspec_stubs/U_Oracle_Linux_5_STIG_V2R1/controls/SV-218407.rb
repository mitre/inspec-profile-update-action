control 'SV-218407' do
  title 'The audit system must be configured to audit login, logout, and session initiation.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', 'The message types that are always recorded to /var/log/audit/audit.log include LOGIN,USER_LOGIN,USER_START,USER_END among others and do not need to be added to audit_rules. 

The log files /var/log/faillog and /var/log/lastlog must be protected from tampering of the login records.

Procedure:
#egrep "faillog|lastlog" /etc/audit/audit.rules|grep "-p (wa|aw)"

If both /var/log/faillog and /var/log/lastlog entries do not exist, this is a finding.'
  desc 'fix', 'Ensure logins. 

Procedure:

Modify /etc/audit/audit.rules to contain:

-w /var/log/faillog -p wa
-w /var/log/lastlog -p wa

Restart the auditd service:
# service auditd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19882r554558_chk'
  tag severity: 'medium'
  tag gid: 'V-218407'
  tag rid: 'SV-218407r603259_rule'
  tag stig_id: 'GEN002800'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag fix_id: 'F-19880r554559_fix'
  tag 'documentable'
  tag legacy: ['V-818', 'SV-65285']
  tag cci: ['CCI-000366', 'CCI-000126']
  tag nist: ['CM-6 b', 'AU-2 c']
end
