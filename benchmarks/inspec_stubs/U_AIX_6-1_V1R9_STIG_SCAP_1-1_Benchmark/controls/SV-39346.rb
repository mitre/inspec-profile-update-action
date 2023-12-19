control 'SV-39346' do
  title 'The cron.allow file must be group-owned by system, bin, sys, or cron.'
  desc 'If the group of the cron.allow is not set to system, bin, sys, or cron, the possibility exists for an unauthorized user to view or edit the list of users permitted to use cron. Unauthorized modification of this file could cause Denial of Service to authorized cron users or provide unauthorized users with the ability to run cron jobs.'
  desc 'fix', 'Change the group owner of the cron.allow file to bin, sys, system, or cron. 
Procedure: 
# chgrp cron /var/adm/cron/cron.allow'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-22391'
  tag rid: 'SV-39346r1_rule'
  tag stig_id: 'GEN003250'
  tag gtitle: 'GEN003250'
  tag fix_id: 'F-33580r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
