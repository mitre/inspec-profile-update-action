control 'SV-45678' do
  title 'The at.deny file must be group-owned by root, bin, sys, or cron.'
  desc 'If the group owner of the at.deny file is not set to root, bin, sys, or cron, unauthorized users could be allowed to view or edit sensitive information contained within the file.  Unauthorized modification could result in Denial of Service to authorized "at" users or provide unauthorized users with the ability to run "at" jobs.'
  desc 'check', 'Check the group ownership of the file.

Procedure:
# ls -lL /etc/at.deny

If the file is not group-owned by root, bin, sys, or cron, this is a finding.'
  desc 'fix', 'Change the group ownership of the at.deny file to root, sys, bin, or cron.

Procedure:
# chgrp root /etc/at.deny'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43044r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22398'
  tag rid: 'SV-45678r1_rule'
  tag stig_id: 'GEN003490'
  tag gtitle: 'GEN003490'
  tag fix_id: 'F-39076r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
