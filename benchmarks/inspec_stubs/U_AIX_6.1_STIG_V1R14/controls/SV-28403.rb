control 'SV-28403' do
  title 'The ftpusers file must exist.'
  desc 'The ftpusers file contains a list of accounts not allowed to use FTP to transfer files. If this file does not exist, then unauthorized accounts can utilize FTP.'
  desc 'check', 'Check for the existence of the ftpusers file.
# ls -l /etc/ftpusers
If the ftpusers file does not exist, this is a finding.'
  desc 'fix', 'Create a /etc/ftpusers file containing a list of accounts not authorized for FTP.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28645r1_chk'
  tag severity: 'medium'
  tag gid: 'V-840'
  tag rid: 'SV-28403r1_rule'
  tag stig_id: 'GEN004880'
  tag gtitle: 'GEN004880'
  tag fix_id: 'F-25674r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
