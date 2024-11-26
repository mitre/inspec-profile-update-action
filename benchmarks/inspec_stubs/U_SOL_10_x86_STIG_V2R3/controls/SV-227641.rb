control 'SV-227641' do
  title 'The /etc/passwd file must be group-owned by root, bin, or sys.'
  desc 'The /etc/passwd file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.'
  desc 'check', 'Check the group ownership of the passwd file.

Procedure:
# ls -lL /etc/passwd

If the file is not group-owned by root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group owner of the /etc/passwd file to root, bin, or sys.

Procedure:
# chgrp root /etc/passwd'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29803r488483_chk'
  tag severity: 'medium'
  tag gid: 'V-227641'
  tag rid: 'SV-227641r603266_rule'
  tag stig_id: 'GEN001379'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29791r488484_fix'
  tag 'documentable'
  tag legacy: ['V-22333', 'SV-39898']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
