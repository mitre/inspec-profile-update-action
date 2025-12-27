control 'SV-45673' do
  title 'The atjobs directory must be group-owned by root, bin, daemon, sys, or at.'
  desc 'If the group of the "atjobs" directory is not root, bin, daemon, sys, or at, unauthorized users could be allowed to view or edit files containing sensitive information within the directory.'
  desc 'check', 'Check the group ownership of the  directory.

Procedure:
# ls -ld /var/spool/atjobs

If the file is not group-owned by root, bin, daemon, sys, or at, this is a finding.'
  desc 'fix', 'Change the group ownership of the  directory to root, bin, sys, daemon or cron.

Procedure:
# chgrp <root|bin|daemon|sys|at> <"atjobs" directory>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43039r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22396'
  tag rid: 'SV-45673r2_rule'
  tag stig_id: 'GEN003430'
  tag gtitle: 'GEN003430'
  tag fix_id: 'F-39071r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
