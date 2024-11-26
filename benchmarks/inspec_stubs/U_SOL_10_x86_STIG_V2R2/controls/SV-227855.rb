control 'SV-227855' do
  title 'The ftpusers file must exist.'
  desc 'The ftpusers file contains a list of accounts not allowed to use FTP to transfer files. If this file does not exist, then unauthorized accounts can utilize FTP.'
  desc 'check', 'Check for the existence of the ftpusers file.
# ls -l /etc/ftpd/ftpusers
If the ftpusers file does not exist, this is a finding.'
  desc 'fix', 'Create a /etc/ftpd/ftpusers file containing a list of accounts not authorized for FTP.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30017r489958_chk'
  tag severity: 'medium'
  tag gid: 'V-227855'
  tag rid: 'SV-227855r603266_rule'
  tag stig_id: 'GEN004880'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-30005r489959_fix'
  tag 'documentable'
  tag legacy: ['V-840', 'SV-28404']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
