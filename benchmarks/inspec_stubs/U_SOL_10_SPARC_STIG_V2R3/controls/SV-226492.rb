control 'SV-226492' do
  title 'System files, programs, and directories must be group-owned by a system group.'
  desc 'Restricting permissions will protect the files from unauthorized modification.'
  desc 'check', 'Check the group ownership of system files, programs, and directories.

Procedure:
# ls -lLa /etc /bin /usr/bin /usr/lbin /usr/ucb /sbin /usr/sbin

If any system file, program, or directory is not group-owned by a system group, this is a finding.'
  desc 'fix', 'Change the group owner of system files to a system group.

Procedure:
# chgrp root /path/to/system/file

(System groups other than root may be used.)'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28653r482861_chk'
  tag severity: 'medium'
  tag gid: 'V-226492'
  tag rid: 'SV-226492r603265_rule'
  tag stig_id: 'GEN001240'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-28641r482862_fix'
  tag 'documentable'
  tag legacy: ['V-796', 'SV-796']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
