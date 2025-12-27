control 'SV-44991' do
  title 'The /etc/passwd file must be group-owned by root, bin, sys or system.'
  desc 'The /etc/passwd file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.'
  desc 'check', 'Check the group ownership of the passwd file.

Procedure:
# ls -lL /etc/passwd

If the file is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group-owner of the /etc/passwd file to root, bin, sys, or system.

Procedure:
# chgrp root /etc/passwd'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42398r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22333'
  tag rid: 'SV-44991r1_rule'
  tag stig_id: 'GEN001379'
  tag gtitle: 'GEN001379'
  tag fix_id: 'F-38408r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
