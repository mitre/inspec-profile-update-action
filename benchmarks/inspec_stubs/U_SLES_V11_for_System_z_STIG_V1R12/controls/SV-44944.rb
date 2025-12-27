control 'SV-44944' do
  title 'System files, programs, and directories must be group-owned by a system group.'
  desc 'Restricting permissions will protect the files from unauthorized modification.'
  desc 'check', 'Check the group-ownership of system files, programs, and directories.

Procedure:
#  ls –lLa /etc /bin /usr/bin /usr/local/bin /sbin /usr/sbin /usr/local/sbin

If any system file, program, or directory is not owned by a system group, this is a finding.'
  desc 'fix', 'Change the group-owner of system files to a system group.

Procedure:
# chgrp root /path/to/system/file

(System groups other than root may be used.)'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42372r1_chk'
  tag severity: 'medium'
  tag gid: 'V-796'
  tag rid: 'SV-44944r1_rule'
  tag stig_id: 'GEN001240'
  tag gtitle: 'GEN001240'
  tag fix_id: 'F-38368r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
