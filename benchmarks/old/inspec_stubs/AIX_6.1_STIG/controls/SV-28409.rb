control 'SV-28409' do
  title 'The ftpusers file must be owned by root.'
  desc 'If the file ftpusers is not owned by root, an unauthorized user may modify the file to allow unauthorized accounts to use FTP.'
  desc 'check', 'Check the ownership of the ftpusers file.
# ls -l /etc/ftpusers
If the ftpusers file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the ftpusers file to root.
# chown root /etc/ftpusers'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28664r1_chk'
  tag severity: 'medium'
  tag gid: 'V-842'
  tag rid: 'SV-28409r1_rule'
  tag stig_id: 'GEN004920'
  tag gtitle: 'GEN004920'
  tag fix_id: 'F-25694r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
