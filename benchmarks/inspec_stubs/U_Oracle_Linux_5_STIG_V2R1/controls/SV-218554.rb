control 'SV-218554' do
  title 'Unencrypted FTP must not be used on the system.'
  desc 'FTP is typically unencrypted and presents confidentiality and integrity risks. FTP may be protected by encryption in certain cases, such as when used in a Kerberos environment. SFTP and FTPS are encrypted alternatives to FTP.'
  desc 'check', 'Perform the following to determine if unencrypted FTP is enabled:

# chkconfig --list gssftp
# chkconfig --list vsftpd

If any of these services are found, ask the SA if these services are encrypted. If they are not, this is a finding.'
  desc 'fix', 'Disable the FTP daemons.

Procedure:
# chkconfig gssftp off
# chkconfig vsftpd off'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20029r555860_chk'
  tag severity: 'medium'
  tag gid: 'V-218554'
  tag rid: 'SV-218554r603259_rule'
  tag stig_id: 'GEN004800'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20027r555861_fix'
  tag 'documentable'
  tag legacy: ['V-12010', 'SV-62885']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
