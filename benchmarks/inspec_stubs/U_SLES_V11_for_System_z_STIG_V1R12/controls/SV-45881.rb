control 'SV-45881' do
  title 'The ftpusers file must be owned by root.'
  desc 'If the file ftpusers is not owned by root, an unauthorized user may modify the file to allow unauthorized accounts to use FTP.'
  desc 'check', 'Check the ownership of the ftpusers file.

Procedure:
For gssftp:
# ls -l /etc/ftpusers

For vsftp:
# ls -l /etc/vsftpd.ftpusers /etc/vsftpd/ftpusers
If the ftpusers file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the ftpusers file to root.
For gssftp:
# chown root /etc/ftpusers

For vsftp:
# chown root /etc/vsftpd.ftpusers /etc/vsftpd/ftpusers'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43198r1_chk'
  tag severity: 'medium'
  tag gid: 'V-842'
  tag rid: 'SV-45881r1_rule'
  tag stig_id: 'GEN004920'
  tag gtitle: 'GEN004920'
  tag fix_id: 'F-39259r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
