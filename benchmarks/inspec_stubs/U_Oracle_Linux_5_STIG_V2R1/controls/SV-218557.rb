control 'SV-218557' do
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
Create an /etc/vsftpd.ftpusers or /etc/vsftpd/ftpusers (as appropriate) file containing a list of accounts not authorized for FTP.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20032r562765_chk'
  tag severity: 'medium'
  tag gid: 'V-218557'
  tag rid: 'SV-218557r603259_rule'
  tag stig_id: 'GEN004880'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-20030r562766_fix'
  tag 'documentable'
  tag legacy: ['V-840', 'SV-62959']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end
