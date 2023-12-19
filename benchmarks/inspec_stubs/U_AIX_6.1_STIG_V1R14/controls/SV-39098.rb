control 'SV-39098' do
  title 'System files, programs, and directories must be group-owned by a system group.'
  desc 'Restricting permissions will protect the files from unauthorized modification.'
  desc 'check', 'Check the group ownership of system files, programs, and directories. 

Procedure: 
# ls -lLa /etc /bin /usr/bin /usr/lbin /usr/ucb /sbin /usr/sbin

If any system file, program, or directory is not group-owned by a system group, this is a finding.  For this check, the system-provided "ipsec" group is also acceptable.'
  desc 'fix', 'Change the group owner of system files to a system group. 

Procedure:
# chgrp sys /path/to/system/file (System groups other than sys may be used.)'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-39523r1_chk'
  tag severity: 'medium'
  tag gid: 'V-796'
  tag rid: 'SV-39098r1_rule'
  tag stig_id: 'GEN001240'
  tag gtitle: 'GEN001240'
  tag fix_id: 'F-33348r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
