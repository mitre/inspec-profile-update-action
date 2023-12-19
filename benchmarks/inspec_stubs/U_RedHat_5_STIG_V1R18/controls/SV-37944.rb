control 'SV-37944' do
  title 'The audit system must be configured to audit login, logout, and session initiation.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', 'The message types that are always recorded to /var/log/audit/audit.log include LOGIN,USER_LOGIN,USER_START,USER_END among others and do not need to be added to audit_rules. 

The log files /var/log/faillog and /var/log/lastlog must be protected from tampering of the login records.

Procedure:

#egrep "faillog|lastlog" /etc/audit/audit.rules|grep "-p (wa|aw)"

If both /var/log/faillog and /var/log/lastlog entries do not exist, this is a finding.'
  desc 'fix', 'Ensure logins 

Procedure:
Modify /etc/audit/audit.rules to contain:

-w /var/log/faillog -p wa
-w /var/log/lastlog -p wa'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37225r1_chk'
  tag severity: 'medium'
  tag gid: 'V-818'
  tag rid: 'SV-37944r1_rule'
  tag stig_id: 'GEN002800'
  tag gtitle: 'GEN002800'
  tag fix_id: 'F-32435r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
