control 'SV-38358' do
  title 'Crontab files must be group-owned by root, sys, cron, or the crontab creators primary group.'
  desc 'To protect the integrity of scheduled system jobs and prevent malicious modification to these jobs, crontab files must be secured.'
  desc 'check', "Check the group ownership of the crontab files.
# ls -lL /var/spool/cron/crontabs

If the group-owner is not root sys (default), cron, or the crontab owner's primary group, this is a finding."
  desc 'fix', 'Change the group owner of the crontab file.
# chgrp root <crontab file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36449r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22385'
  tag rid: 'SV-38358r1_rule'
  tag stig_id: 'GEN003050'
  tag gtitle: 'GEN003050'
  tag fix_id: 'F-31788r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
