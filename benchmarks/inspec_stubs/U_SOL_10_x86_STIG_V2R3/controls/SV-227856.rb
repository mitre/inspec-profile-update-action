control 'SV-227856' do
  title 'The ftpusers file must contain account names not allowed to use FTP.'
  desc 'The ftpusers file contains a list of accounts that are not allowed to use FTP to transfer files. If the file does not contain the names of all accounts not authorized to use FTP, then unauthorized use of FTP may take place.'
  desc 'check', 'Check the contents of the ftpusers file.

Procedure:
# more /etc/ftpd/ftpusers

If the system has accounts not allowed to use FTP that are not listed in the ftpusers file, this is a finding.'
  desc 'fix', 'Add accounts not allowed to use FTP to the /etc/ftpd/ftpusers file.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30018r489961_chk'
  tag severity: 'medium'
  tag gid: 'V-227856'
  tag rid: 'SV-227856r854507_rule'
  tag stig_id: 'GEN004900'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-30006r489962_fix'
  tag 'documentable'
  tag legacy: ['V-841', 'SV-28407']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
