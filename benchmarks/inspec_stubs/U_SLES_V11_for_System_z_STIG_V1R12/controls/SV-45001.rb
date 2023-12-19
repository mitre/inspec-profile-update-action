control 'SV-45001' do
  title 'The /etc/shadow file (or equivalent) must be group-owned by root, bin, sys, or shadow.'
  desc 'The /etc/shadow file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.  The file also contains password hashes which must not be accessible to users other than root.'
  desc 'check', 'Check the ownership of the /etc/shadow file.

Procedure:
# ls -lL /etc/shadow

If the file is not group-owned by root, bin, sys, or shadow, this is a finding.'
  desc 'fix', 'Change the group-owner of the /etc/shadow file.

Procedure:
# chgrp root /etc/shadow'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42406r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22339'
  tag rid: 'SV-45001r2_rule'
  tag stig_id: 'GEN001410'
  tag gtitle: 'GEN001410'
  tag fix_id: 'F-38416r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
