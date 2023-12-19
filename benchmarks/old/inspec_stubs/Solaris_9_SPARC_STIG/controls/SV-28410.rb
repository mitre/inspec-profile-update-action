control 'SV-28410' do
  title 'The ftpusers file must be owned by root.'
  desc 'If the file ftpusers is not owned by root, an unauthorized user may modify the file to allow unauthorized accounts to use FTP.'
  desc 'fix', 'Change the owner of the ftpusers file to root.
# chown root /etc/ftpd/ftpusers'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-842'
  tag rid: 'SV-28410r1_rule'
  tag stig_id: 'GEN004920'
  tag gtitle: 'GEN004920'
  tag fix_id: 'F-25695r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
