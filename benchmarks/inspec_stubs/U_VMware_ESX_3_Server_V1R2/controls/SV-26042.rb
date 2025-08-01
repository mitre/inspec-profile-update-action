control 'SV-26042' do
  title 'The cron.allow file must be group-owned by root, bin, sys, or cron.'
  desc 'If the group of the cron.allow is not set to root, bin, sys, or cron, the possibility exists for an unauthorized user to view or edit the list of users permitted to use cron. Unauthorized modification of this file could cause Denial-of-Service to authorized cron users or provide unauthorized users with the ability to run cron jobs.'
  desc 'check', 'Determine the group owner of the cron.allow file.

Procedure:
# ls -lL cron.allow

If the group owner is not root, bin, sys, or cron, this is a finding.'
  desc 'fix', 'Change the group owner of the cron.allow file to root, bin, sys, or cron.

Procedure:
# chgrp root cron.allow'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29223r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22391'
  tag rid: 'SV-26042r1_rule'
  tag stig_id: 'GEN003250'
  tag gtitle: 'GEN003250'
  tag fix_id: 'F-26244r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
