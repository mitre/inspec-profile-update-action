control 'SV-45879' do
  title 'The ftpusers file must exist.'
  desc 'The ftpusers file contains a list of accounts not allowed to use FTP to transfer files. If this file does not exist, then unauthorized accounts can utilize FTP.'
  desc 'check', 'Check for the existence of the ftpusers file.

Procedure:
For gssftp:
# ls -l /etc/ftpusers

For vsftp:
# ls -l /etc/vsftpd.ftpusers
or
# ls -l /etc/vsftpd/ftpusers
If the appropriate ftpusers file for the running FTP service does not exist, this is a finding.'
  desc 'fix', 'Create an ftpusers file appropriate for the running FTP service.
For gssftp:
Create an /etc/ftpusers file containing a list of accounts not authorized for FTP.

For vsftp:
Create an /etc/vfsftpd.ftpusers or /etc/vfsftpd/ftpusers (as appropriate) file containing a list of accounts not authorized for FTP.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43196r1_chk'
  tag severity: 'medium'
  tag gid: 'V-840'
  tag rid: 'SV-45879r1_rule'
  tag stig_id: 'GEN004880'
  tag gtitle: 'GEN004880'
  tag fix_id: 'F-39257r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
