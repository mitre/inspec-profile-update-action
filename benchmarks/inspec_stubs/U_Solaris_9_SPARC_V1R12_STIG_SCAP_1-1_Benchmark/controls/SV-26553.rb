control 'SV-26553' do
  title 'The cron.allow file must be group-owned by root, bin, or sys.'
  desc 'If the group of the cron.allow is not set to root, bin, or sys, the possibility exists for an unauthorized user to view or edit the list of users permitted to use cron.  Unauthorized modification of this file could cause Denial of Service to authorized cron users or provide unauthorized users with the ability to run cron jobs.'
  desc 'fix', 'Change the group ownership of the file.

Procedure:
# chgrp root /etc/cron.d/cron.allow'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-22391'
  tag rid: 'SV-26553r1_rule'
  tag stig_id: 'GEN003250'
  tag gtitle: 'GEN003250'
  tag fix_id: 'F-23797r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
