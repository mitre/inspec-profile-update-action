control 'SV-38749' do
  title 'System audit tool executables must be owned by root.'
  desc 'To prevent unauthorized access or manipulation of system audit logs, the tools for manipulating those logs must be protected.'
  desc 'check', 'Determine if the system audit tool executables are owned by root.  Audit tools include, but are not limited to, audit, auditcat, auditconv, auditpr, auditselect, auditstream, auditbin, and auditmerge.

Procedure:
ls -lL `which <audit tool executable>`

If any system audit tool executable is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the system audit tool executables to root. 
#chown root  <system audit tool executable>'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37197r1_chk'
  tag severity: 'low'
  tag gid: 'V-22370'
  tag rid: 'SV-38749r1_rule'
  tag stig_id: 'GEN002715'
  tag gtitle: 'GEN002715'
  tag fix_id: 'F-32467r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
