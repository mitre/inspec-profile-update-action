control 'SV-227760' do
  title 'The cron.allow file must be group-owned by root, bin, or sys.'
  desc 'If the group of the cron.allow is not set to root, bin, or sys, the possibility exists for an unauthorized user to view or edit the list of users permitted to use cron.  Unauthorized modification of this file could cause Denial of Service to authorized cron users or provide unauthorized users with the ability to run cron jobs.'
  desc 'check', 'Check the group ownership of the file.

Procedure:
# ls -lL /etc/cron.d/cron.allow

If the file is not group-owned by root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group ownership of the file.

Procedure:
# chgrp root /etc/cron.d/cron.allow'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29922r488864_chk'
  tag severity: 'medium'
  tag gid: 'V-227760'
  tag rid: 'SV-227760r603266_rule'
  tag stig_id: 'GEN003250'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29910r488865_fix'
  tag 'documentable'
  tag legacy: ['V-22391', 'SV-26553']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
