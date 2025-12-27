control 'SV-28634' do
  title 'Unencrypted FTP must not be used on the system.'
  desc 'FTP is typically unencrypted and, therefore, presents confidentiality and integrity risks.  FTP may be protected by encryption in certain cases, such as when used in a Kerberos environment.   SFTP and FTPS are encrypted alternatives to FTP.'
  desc 'check', 'Determine if unencrypted FTP is enabled.

Procedure:
# grep ftp /etc/inetd.conf 

If this service is found, and is not commented out, ask the SA if the services are encrypted.  If they are not, this is a finding.'
  desc 'fix', 'Edit /etc/inetd.conf and comment out or remove the ftp service.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-28886r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12010'
  tag rid: 'SV-28634r1_rule'
  tag stig_id: 'GEN004800'
  tag gtitle: 'GEN004800'
  tag fix_id: 'F-25908r1_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
