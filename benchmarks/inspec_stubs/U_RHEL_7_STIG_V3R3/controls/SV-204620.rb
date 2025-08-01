control 'SV-204620' do
  title 'The Red Hat Enterprise Linux operating system must not have a File Transfer Protocol (FTP) server package installed unless needed.'
  desc 'The FTP service provides an unencrypted remote access that does not provide for the confidentiality and integrity of user passwords or the remote session. If a privileged user were to log on using this service, the privileged user password could be compromised. SSH or other encrypted file transfer methods must be used in place of this service.'
  desc 'check', 'Verify an FTP server has not been installed on the system.

Check to see if an FTP server has been installed with the following commands:

# yum list installed vsftpd

 vsftpd-3.0.2.el7.x86_64.rpm

If "vsftpd" is installed and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Document the "vsftpd" package with the ISSO as an operational requirement or remove it from the system with the following command:

# yum remove vsftpd'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4744r89052_chk'
  tag severity: 'high'
  tag gid: 'V-204620'
  tag rid: 'SV-204620r603261_rule'
  tag stig_id: 'RHEL-07-040690'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-4744r89053_fix'
  tag 'documentable'
  tag legacy: ['SV-86923', 'V-72299']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
