control 'SV-248903' do
  title 'A File Transfer Protocol (FTP) server package must not be installed unless mission essential on OL 8.'
  desc 'The FTP service provides an unencrypted remote access that does not provide for the confidentiality and integrity of user passwords or the remote session. If a privileged user were to log on using this service, the privileged user password could be compromised. SSH or other encrypted file transfer methods must be used in place of this service.'
  desc 'check', 'Verify an FTP server has not been installed on the system with the following commands: 
 
$ sudo yum list installed | grep ftpd 
 
vsftpd-3.0.3.el8.x86_64.rpm 
 
If an FTP server is installed and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Document the FTP server package with the ISSO as an operational requirement or remove it from the system with the following command: 
 
$ sudo yum remove vsftpd'
  impact 0.7
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52337r780273_chk'
  tag severity: 'high'
  tag gid: 'V-248903'
  tag rid: 'SV-248903r780275_rule'
  tag stig_id: 'OL08-00-040360'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52291r780274_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
