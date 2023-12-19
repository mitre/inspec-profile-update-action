control 'SV-226601' do
  title 'The audit system must be configured to audit file deletions.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', '# grep flags /etc/security/audit_control 
Confirm flags fd or +fd and -fd are configured.'
  desc 'fix', 'Edit /etc/security/audit_control and add the fd to the flags list.
Load the new audit configuration.
# auditconfig -conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28762r483215_chk'
  tag severity: 'medium'
  tag gid: 'V-226601'
  tag rid: 'SV-226601r603265_rule'
  tag stig_id: 'GEN002740'
  tag gtitle: 'SRG-OS-000062'
  tag fix_id: 'F-28750r483216_fix'
  tag 'documentable'
  tag legacy: ['SV-27292', 'V-815']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
