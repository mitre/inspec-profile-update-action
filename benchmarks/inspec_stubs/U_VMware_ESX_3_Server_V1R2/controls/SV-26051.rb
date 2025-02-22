control 'SV-26051' do
  title 'The at.deny file must be group-owned by root, bin, sys, or cron.'
  desc 'If the group owner of the at.deny file is not set to root, bin, sys, or cron, unauthorized users could be allowed to view or edit sensitive information contained within the file.  Unauthorized modification could result in Denial-of-Service to authorized "at" users or provide unauthorized users with the ability to run "at" jobs.'
  desc 'check', 'Determine the group owner of the at.deny file.

Procedure:
# ls -lL at.deny

If the group-owner is not root, bin, sys, or cron, this is a finding.'
  desc 'fix', 'Change the group owner of the at.deny file to root, bin, sys, or cron.

Procedure:
# chgrp root at.deny'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29231r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22398'
  tag rid: 'SV-26051r1_rule'
  tag stig_id: 'GEN003490'
  tag gtitle: 'GEN003490'
  tag fix_id: 'F-26253r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
