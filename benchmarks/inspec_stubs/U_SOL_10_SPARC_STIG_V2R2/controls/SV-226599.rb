control 'SV-226599' do
  title 'The audit system must be configured to audit failed attempts to access files and programs.'
  desc 'If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.'
  desc 'check', 'Check the system audit configuration to determine if failed attempts to access files and programs are audited.
# more /etc/security/audit_control
If flags -fr or fr are not configured, this is a finding.'
  desc 'fix', 'Edit /etc/security/audit_control and add the fr or -fr flags to the flags list.
Load the new audit configuration.
# auditconfig -conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28760r483209_chk'
  tag severity: 'medium'
  tag gid: 'V-226599'
  tag rid: 'SV-226599r603265_rule'
  tag stig_id: 'GEN002720'
  tag gtitle: 'SRG-OS-000064'
  tag fix_id: 'F-28748r483210_fix'
  tag 'documentable'
  tag legacy: ['V-814', 'SV-27287']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
