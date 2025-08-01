control 'SV-215268' do
  title 'AIX system files, programs, and directories must be group-owned by a system group.'
  desc 'Restricting permissions will protect the files from unauthorized modification.'
  desc 'check', 'Check the group ownership of system files, programs, and directories run the following command: 
# ls -lLa /etc /bin /usr/bin /usr/lbin /usr/ucb /sbin /usr/sbin 

If any system file, program, or directory is not group-owned by a system group, this is a finding. 

Note: For this check, the system-provided "ipsec" group is also acceptable.'
  desc 'fix', 'Change the group owner of system files to a system group by running the following command:
 # chgrp sys /path/to/system/file 

Note: System groups other than "sys" may be used.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16466r294255_chk'
  tag severity: 'medium'
  tag gid: 'V-215268'
  tag rid: 'SV-215268r508663_rule'
  tag stig_id: 'AIX7-00-002072'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-16464r294256_fix'
  tag 'documentable'
  tag legacy: ['SV-101571', 'V-91473']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
