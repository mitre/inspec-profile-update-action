control 'SV-44941' do
  title 'All system files, programs, and directories must be owned by a system account.'
  desc 'Restricting permissions will protect the files from unauthorized modification.'
  desc 'check', 'Check the ownership of system files, programs, and directories.

Procedure:
# ls -lLa /etc /bin /usr/bin /usr/local/bin /sbin /usr/sbin /usr/local/sbin

If any of the system files, programs, or directories are not owned by a system account, this is a finding.'
  desc 'fix', 'Change the owner of system files, programs, and directories to a system account.

Procedure:
# chown root /some/system/file

(A different system user may be used in place of root.)'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42371r1_chk'
  tag severity: 'medium'
  tag gid: 'V-795'
  tag rid: 'SV-44941r1_rule'
  tag stig_id: 'GEN001220'
  tag gtitle: 'GEN001220'
  tag fix_id: 'F-38366r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
