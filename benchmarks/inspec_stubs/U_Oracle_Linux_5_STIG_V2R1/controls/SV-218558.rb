control 'SV-218558' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20033r562768_chk'
  tag severity: 'medium'
  tag gid: 'V-218558'
  tag rid: 'SV-218558r603259_rule'
  tag stig_id: 'GEN004900'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-20031r562769_fix'
  tag 'documentable'
  tag legacy: ['V-841', 'SV-62981']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end
