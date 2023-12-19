control 'SV-26018' do
  title 'System audit tool executables must be group-owned by root, bin, sys, or system.'
  desc 'To prevent unauthorized access or manipulation of system audit logs, the tools for manipulating those logs must be protected.'
  desc 'check', 'Determine the group ownership of system audit tool executables.

Procedure:
# ls -lL <audit tool executable>

If any system audit tool executable is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group owner of system audit tool executables to root, bin, sys, or system.

Procedure:
# chgrp system < system audit tool executable>'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29202r1_chk'
  tag severity: 'low'
  tag gid: 'V-22371'
  tag rid: 'SV-26018r1_rule'
  tag stig_id: 'GEN002716'
  tag gtitle: 'GEN002716'
  tag fix_id: 'F-26224r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
