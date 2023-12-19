control 'SV-52091' do
  title 'The ftpusers file must contain account names not allowed to use FTP.'
  desc 'The ftpusers file contains a list of accounts not allowed to use FTP to transfer files. If the file does not contain the names of all accounts not authorized to use FTP, then unauthorized use of FTP may take place.'
  desc 'check', 'Check the contents of the ftpusers file. 
For gssftp:
# more /etc/ftpusers

For vsftp:
# more /etc/vsftpd.ftpusers /etc/vfsftpd/ftpusers
If the system has accounts not allowed to use FTP and not listed in the ftpusers file, this is a finding.'
  desc 'fix', 'For gssftp:
Add accounts not allowed to use FTP to the /etc/ftpusers file.
For vsftp:
Add accounts not allowed to use FTP to the /etc/vsftpd.ftpusers or /etc/vsftpd/ftpusers file (as appropriate).'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36191r1_chk'
  tag severity: 'medium'
  tag gid: 'V-841'
  tag rid: 'SV-52091r1_rule'
  tag stig_id: 'GEN004900'
  tag gtitle: 'GEN004900'
  tag fix_id: 'F-45121r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
