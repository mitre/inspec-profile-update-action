control 'SV-227645' do
  title 'The /etc/group file must be group-owned by root, bin, or sys.'
  desc 'The /etc/group file is critical to system security and must be protected from unauthorized modification.  The group file contains a list of system groups and associated information.'
  desc 'check', 'Check the group ownership of the /etc/group file.

Procedure:
# ls -lL /etc/group

If the file is not group-owned by root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group owner of the /etc/group file.

Procedure:
# chgrp root /etc/group'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29807r488495_chk'
  tag severity: 'medium'
  tag gid: 'V-227645'
  tag rid: 'SV-227645r603266_rule'
  tag stig_id: 'GEN001392'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29795r488496_fix'
  tag 'documentable'
  tag legacy: ['V-22336', 'SV-39899']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
