control 'SV-26508' do
  title 'System audit tool executables must be group-owned by root, bin, or sys.'
  desc 'To prevent unauthorized access or manipulation of system audit logs, the tools for manipulating those logs must be protected.'
  desc 'fix', 'Change the group-owner of the audit tool executable to root, bin, or sys.

Procedure:
# chgrp root <audit tool executable>'
  impact 0.3
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'low'
  tag gid: 'V-22371'
  tag rid: 'SV-26508r1_rule'
  tag stig_id: 'GEN002716'
  tag gtitle: 'GEN002716'
  tag fix_id: 'F-34061r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
