control 'SV-51983' do
  title 'The ftpusers file must exist.'
  desc 'The ftpusers file contains a list of accounts not allowed to use FTP to transfer files. If this file does not exist, then unauthorized accounts can utilize FTP.'
  desc 'fix', 'Create an ftpusers file appropriate for the running FTP service.
For gssftp:
Create an /etc/ftpusers file containing a list of accounts not authorized for FTP.

For vsftp:
Create an /etc/vsftpd.ftpusers or /etc/vsftpd/ftpusers (as appropriate) file containing a list of accounts not authorized for FTP.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-840'
  tag rid: 'SV-51983r1_rule'
  tag stig_id: 'GEN004880'
  tag gtitle: 'GEN004880'
  tag fix_id: 'F-45028r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
