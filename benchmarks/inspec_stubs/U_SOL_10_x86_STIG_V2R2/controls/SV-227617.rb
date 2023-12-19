control 'SV-227617' do
  title 'All system files, programs, and directories must be owned by a system account.'
  desc 'Restricting permissions will protect the files from unauthorized modification.'
  desc 'check', 'Check the ownership of system files, programs, and directories.

Procedure:
# ls -lLa /etc /bin /usr/bin /usr/lbin /usr/ucb /sbin /usr/sbin

If any of the system files, programs, or directories are not owned by a system account, this is a finding.'
  desc 'fix', 'Change the owner of system files, programs, and directories to a system account.

Procedure:
# chown root /some/system/file

(A different system user may be used in place of root.)'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29779r488408_chk'
  tag severity: 'medium'
  tag gid: 'V-227617'
  tag rid: 'SV-227617r603266_rule'
  tag stig_id: 'GEN001220'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-29767r488409_fix'
  tag 'documentable'
  tag legacy: ['V-795', 'SV-795']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
