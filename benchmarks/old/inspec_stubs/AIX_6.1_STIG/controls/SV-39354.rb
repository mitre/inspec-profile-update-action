control 'SV-39354' do
  title 'The at.allow file must be group-owned by system, bin, sys, or cron.'
  desc 'If the group-owner of the at.allow file is not set to system, bin, sys, or cron, unauthorized users could be allowed to view or edit the list of users permitted to run at jobs.  Unauthorized modification could result in Denial of Service to authorized at users or provide unauthorized users with the ability to run at jobs.'
  desc 'check', 'Determine the group owner of the at.allow file. 
Procedure: 
# ls -lL /var/adm/cron/at.allow 
If the group-owner is not bin, sys, system, or cron, this is a finding.'
  desc 'fix', 'Change the group owner of the at.allow file to sys, system, bin, or cron. 
Procedure: 
# chgrp cron /var/adm/cron/at.allow'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38301r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22397'
  tag rid: 'SV-39354r1_rule'
  tag stig_id: 'GEN003470'
  tag gtitle: 'GEN003470'
  tag fix_id: 'F-33589r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
