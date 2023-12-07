control 'SV-28404' do
  title 'The ftpusers file must exist.'
  desc 'The ftpusers file contains a list of accounts not allowed to use FTP to transfer files. If this file does not exist, then unauthorized accounts can utilize FTP.'
  desc 'fix', 'Create a /etc/ftpd/ftpusers file containing a list of accounts not authorized for FTP.'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-840'
  tag rid: 'SV-28404r1_rule'
  tag stig_id: 'GEN004880'
  tag gtitle: 'GEN004880'
  tag fix_id: 'F-25675r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-2, ECCD-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
