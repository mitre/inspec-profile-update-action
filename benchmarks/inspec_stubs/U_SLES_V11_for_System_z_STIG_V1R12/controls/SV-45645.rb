control 'SV-45645' do
  title 'The cron.deny file must be group-owned by root, bin, sys.'
  desc 'Cron daemon control files restrict the scheduling of automated tasks and must be protected.  Unauthorized modification of the cron.deny file could result in Denial of Service to authorized cron users or could provide unauthorized users with the ability to run cron jobs.'
  desc 'check', 'Check the group ownership of the file.

Procedure:
# ls -lL /etc/cron.deny

If the file is not group-owned by root, bin or sys this is a finding.'
  desc 'fix', 'Change the group ownership of the file.
# chgrp root /etc/cron.deny'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43011r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22394'
  tag rid: 'SV-45645r2_rule'
  tag stig_id: 'GEN003270'
  tag gtitle: 'GEN003270'
  tag fix_id: 'F-39043r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
