control 'SV-27213' do
  title 'All system start-up files must be group-owned by root, sys, or bin.'
  desc 'If system start-up files do not have a group owner of root or a system group, the files may be modified by malicious users or intruders.'
  desc 'fix', 'Change the group ownership of the run control script(s) with incorrect group ownership.

Procedure:
# chgrp root <run control script>'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-4090'
  tag rid: 'SV-27213r1_rule'
  tag stig_id: 'GEN001680'
  tag gtitle: 'GEN001680'
  tag fix_id: 'F-24459r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
