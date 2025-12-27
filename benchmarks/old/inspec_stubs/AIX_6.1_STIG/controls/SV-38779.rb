control 'SV-38779' do
  title 'System audit tool executables must not have extended ACLs.'
  desc 'To prevent unauthorized access or manipulation of system audit logs, the tools for manipulating those logs must be protected.'
  desc 'check', 'Determine if system audit tool executables have extended ACLs  Audit tools include, but are not limited to audit, auditcat, auditconv, auditpr, auditselect, auditstream, auditbin, and auditmerge.
Procedure:
#aclget <system audit tool executable> 
Check if extended permissions are disabled.  If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the system audit tool executable(s) and disable extended permissions.

#acledit <system audit tool executable>'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37202r1_chk'
  tag severity: 'low'
  tag gid: 'V-22373'
  tag rid: 'SV-38779r1_rule'
  tag stig_id: 'GEN002718'
  tag gtitle: 'GEN002718'
  tag fix_id: 'F-32469r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
