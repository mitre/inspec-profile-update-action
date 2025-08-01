control 'SV-45876' do
  title 'Unencrypted FTP must not be used on the system.'
  desc 'FTP is typically unencrypted and presents confidentiality and integrity risks. FTP may be protected by encryption in certain cases, such as when used in a Kerberos environment. SFTP and FTPS are encrypted alternatives to FTP.'
  desc 'check', 'Perform the following to determine if unencrypted FTP is enabled:

# chkconfig --list pure-ftpd
# chkconfig --list gssftp
# chkconfig --list vsftpd

If any of these services are found, ask the SA if these services are encrypted.

If they are not, this is a finding.'
  desc 'fix', 'Disable the FTP daemons.

Procedure:
# chkconfig pure-ftpd off
# chkconfig gssftp off
# chkconfig vsftpd off'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43193r2_chk'
  tag severity: 'medium'
  tag gid: 'V-12010'
  tag rid: 'SV-45876r2_rule'
  tag stig_id: 'GEN004800'
  tag gtitle: 'GEN004800'
  tag fix_id: 'F-39254r2_fix'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
