control 'SV-35103' do
  title 'The ftpusers file must contain account names not allowed to use FTP.'
  desc 'The ftpusers file contains a list of accounts not allowed to use FTP to transfer files. If the file does not contain the names of all accounts not authorized to use FTP, then unauthorized use of FTP may take place.'
  desc 'check', 'Check the contents of the ftpusers file. 
# more /etc/ftpd/ftpusers
OR alternatively
# find / -type f -name ftpusers -exec ls -lL {} \\;

If the system has accounts not allowed to use FTP and not 
listed in the ftpusers file, this is a finding.'
  desc 'fix', 'Add accounts not allowed to use FTP to the 
/etc/ftpd/ftpusers (or equivalent) file.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36583r1_chk'
  tag severity: 'medium'
  tag gid: 'V-841'
  tag rid: 'SV-35103r1_rule'
  tag stig_id: 'GEN004900'
  tag gtitle: 'GEN004900'
  tag fix_id: 'F-31951r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
