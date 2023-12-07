control 'SV-26563' do
  title 'The cron.deny file must be group-owned by root, bin, or sys.'
  desc 'Cron daemon control files restrict the scheduling of automated tasks and must be protected.  Unauthorized modification of the cron.deny file could result in Denial of Service to authorized cron users or could provide unauthorized users with the ability to run cron jobs.'
  desc 'fix', 'Change the group ownership of the file to root, sys, or bin.

Procedure:
# chgrp root /etc/cron.d/cron.deny'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-22394'
  tag rid: 'SV-26563r1_rule'
  tag stig_id: 'GEN003270'
  tag gtitle: 'GEN003270'
  tag fix_id: 'F-23807r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
