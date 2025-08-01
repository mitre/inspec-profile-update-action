control 'SV-226607' do
  title 'The audit system must be configured to audit login, logout, and session initiation.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', "Check the system's audit configuration.

# grep lo /etc/security/audit_control

If the lo flag is not set, and both the +lo and -lo flags are not set, this is a finding.
If the lo naflag is not set, and both the +lo and -lo naflags are not set, this is a finding."
  desc 'fix', 'Edit /etc/security/audit_control and add lo to the flags list and naflags list.
Load the new audit configuration.
# auditconfig -conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28768r483233_chk'
  tag severity: 'medium'
  tag gid: 'V-226607'
  tag rid: 'SV-226607r603265_rule'
  tag stig_id: 'GEN002800'
  tag gtitle: 'SRG-OS-000470'
  tag fix_id: 'F-28756r483234_fix'
  tag 'documentable'
  tag legacy: ['V-818', 'SV-27303']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
