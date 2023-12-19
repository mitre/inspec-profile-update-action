control 'SV-226874' do
  title 'The at.deny file must be group-owned by root, bin, or sys.'
  desc 'If the group owner of the at.deny file is not set to root, bin, or sys, unauthorized users could be allowed to view or edit sensitive information contained within the file.  Unauthorized modification could result in Denial of Service to authorized "at" users or provide unauthorized users with the ability to run "at" jobs.'
  desc 'check', 'Check the group ownership of the file.

Procedure:
# ls -lL /etc/cron.d/at.deny

If the file is not group-owned by root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group ownership of the at.deny file to root, bin, or sys.

Procedure:
# chgrp root /etc/cron.d/at.deny'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29036r484906_chk'
  tag severity: 'medium'
  tag gid: 'V-226874'
  tag rid: 'SV-226874r603265_rule'
  tag stig_id: 'GEN003490'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29024r484907_fix'
  tag 'documentable'
  tag legacy: ['V-22398', 'SV-26573']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
