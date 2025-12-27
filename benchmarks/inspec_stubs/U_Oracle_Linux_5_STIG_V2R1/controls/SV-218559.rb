control 'SV-218559' do
  title 'The ftpusers file must be owned by root.'
  desc 'If the file ftpusers is not owned by root, an unauthorized user may modify the file to allow unauthorized accounts to use FTP.'
  desc 'check', 'Check the ownership of the ftpusers file.

Procedure:
For gssftp:
# ls -l /etc/ftpusers

For vsftp:
# ls -l /etc/vsftpd.ftpusers /etc/vsftpd/ftpusers

If the ftpusers file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the ftpusers file to root.
For gssftp:
# chown root /etc/ftpusers

For vsftp:
# chown root /etc/vsftpd.ftpusers /etc/vsftpd/ftpusers'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20034r562771_chk'
  tag severity: 'medium'
  tag gid: 'V-218559'
  tag rid: 'SV-218559r603259_rule'
  tag stig_id: 'GEN004920'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-20032r562772_fix'
  tag 'documentable'
  tag legacy: ['V-842', 'SV-63009']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end
