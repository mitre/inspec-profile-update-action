control 'SV-39176' do
  title 'Unencrypted FTP must not be used on the system.'
  desc 'FTP is typically unencrypted and, therefore, presents confidentiality and integrity risks. FTP may be protected by encryption in certain cases, such as when used in a Kerberos environment. SFTP and FTPS are encrypted alternatives to FTP.'
  desc 'check', 'Determine if unencrypted ftp is enabled.

Procedure:
# grep ftp /etc/inetd.conf 

If the service is found and is active, ask the SA if it is encrypted.

If it is not, this is a finding.'
  desc 'fix', 'Edit /etc/inetd.conf and comment out or remove the ftp service line.

# vi /etc/inetd.conf

Restart the inetd service.

# refresh -s inetd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38153r3_chk'
  tag severity: 'medium'
  tag gid: 'V-12010'
  tag rid: 'SV-39176r2_rule'
  tag stig_id: 'GEN004800'
  tag gtitle: 'GEN004800'
  tag fix_id: 'F-33430r2_fix'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
