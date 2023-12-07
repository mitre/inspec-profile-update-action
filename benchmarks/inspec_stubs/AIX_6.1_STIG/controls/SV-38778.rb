control 'SV-38778' do
  title 'System audit tool executables must have mode 0750 or less permissive.'
  desc 'To prevent unauthorized access or manipulation of system audit logs, the tools for manipulating those logs must be protected.'
  desc 'check', 'Determine if system audit tool executables have a mode more permissive than 0750. If any do, this is a finding.  Audit tools include, but are not limited to, audit, auditcat, auditconv, auditpr, auditselect, auditstream, auditbin, and auditmerge.'
  desc 'fix', 'Many audit tools have SUID bit set.  Before changing permissions on system audit tool executables,  check the file permissions for SUID bits. Change the mode of system audit tool executables to 0750. 
#chmod 0750 or 4750  <system audit tool executable>
Document all changes made.'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37199r1_chk'
  tag severity: 'low'
  tag gid: 'V-22372'
  tag rid: 'SV-38778r1_rule'
  tag stig_id: 'GEN002717'
  tag gtitle: 'GEN002717'
  tag fix_id: 'F-32468r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
