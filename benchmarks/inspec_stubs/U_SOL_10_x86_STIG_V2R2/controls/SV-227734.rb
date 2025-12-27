control 'SV-227734' do
  title 'The audit system must be configured to audit all discretionary access control permission modifications.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', "Check the system's audit configuration.
# grep flags /etc/security/audit_control
Confirm flags fm or +fm and -fm are configured."
  desc 'fix', 'Edit /etc/security/audit_control and add fm to the flags list.
Load the new audit configuration.
# auditconfig -conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29896r488786_chk'
  tag severity: 'medium'
  tag gid: 'V-227734'
  tag rid: 'SV-227734r603266_rule'
  tag stig_id: 'GEN002820'
  tag gtitle: 'SRG-OS-000064'
  tag fix_id: 'F-29884r488787_fix'
  tag 'documentable'
  tag legacy: ['V-819', 'SV-27309']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
