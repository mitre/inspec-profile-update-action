control 'SV-39352' do
  title 'The "at" directory must be group-owned by system, bin, sys, or cron.'
  desc 'If the group of the "at" directory is not system, bin, sys, or cron, unauthorized users could be allowed to view or edit files containing sensitive information within the directory.'
  desc 'check', 'Check the group ownership of the file.

Procedure:
# ls -ld /var/spool/cron/atjobs 

If the file is not group-owned by bin, sys, system, or cron, this is a finding.'
  desc 'fix', 'Change the group ownership of the file to bin, sys, system, or cron.

Procedure:
# chgrp cron /var/spool/cron/atjobs'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38298r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22396'
  tag rid: 'SV-39352r1_rule'
  tag stig_id: 'GEN003430'
  tag gtitle: 'GEN003430'
  tag fix_id: 'F-33587r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
