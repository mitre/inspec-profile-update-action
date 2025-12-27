control 'SV-26050' do
  title 'The at.allow file must be group-owned by root, bin, sys, or cron.'
  desc 'If the group owner of the at.allow file is not set to root, bin, sys, or cron, unauthorized users could be allowed to view or edit the list of users permitted to run "at" jobs.  Unauthorized modification could result in Denial-of-Service to authorized "at" users or provide unauthorized users with the ability to run "at" jobs.'
  desc 'check', 'Determine the group owner of the at.allow file.

Procedure:
# ls -lL at.allow

If the group owner is not root, bin, sys, or cron,  this is a finding.'
  desc 'fix', 'Change the group owner of the at.allow file to root, sys, bin, or cron.

Procedure:
# chgrp root at.allow'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29230r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22397'
  tag rid: 'SV-26050r1_rule'
  tag stig_id: 'GEN003470'
  tag gtitle: 'GEN003470'
  tag fix_id: 'F-26252r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
