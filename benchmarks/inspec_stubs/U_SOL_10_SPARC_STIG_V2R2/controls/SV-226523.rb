control 'SV-226523' do
  title 'The /etc/shadow file (or equivalent) must be group-owned by root, bin, or sys.'
  desc 'The /etc/shadow file contains the list of local system accounts.  It is vital to system security and must be protected from unauthorized modification.  The file also contains password hashes which must not be accessible to users other than root.'
  desc 'check', 'Check the ownership of the /etc/shadow file.

Procedure:
# ls -lL /etc/shadow

If the file is not group-owned by root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group owner of the /etc/shadow file.

Procedure:
# chgrp root /etc/shadow'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28684r482957_chk'
  tag severity: 'medium'
  tag gid: 'V-226523'
  tag rid: 'SV-226523r603265_rule'
  tag stig_id: 'GEN001410'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28672r482958_fix'
  tag 'documentable'
  tag legacy: ['V-22339', 'SV-39900']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
