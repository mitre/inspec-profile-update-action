control 'SV-38336' do
  title 'The /etc/passwd file must be group-owned by root, bin, sys, or system.'
  desc 'The /etc/passwd file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.'
  desc 'check', 'Check the group ownership of the passwd file.

Procedure:
# ls -lL /etc/passwd

If the file is not group-owned by root, bin, sys, or other, this is a finding.'
  desc 'fix', 'Change the group owner of the /etc/passwd file to root, bin, sys, or other.

Procedure:
# chgrp root /etc/passwd'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36344r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22333'
  tag rid: 'SV-38336r1_rule'
  tag stig_id: 'GEN001379'
  tag gtitle: 'GEN001379'
  tag fix_id: 'F-31603r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
