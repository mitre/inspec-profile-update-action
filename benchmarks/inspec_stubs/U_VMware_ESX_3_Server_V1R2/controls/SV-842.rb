control 'SV-842' do
  title 'The ftpusers file must be owned by root.'
  desc 'If the file ftpusers is not owned by root, an unauthorized user may modify the file to allow unauthorized accounts to use FTP.'
  desc 'check', 'Check the ownership of the ftpusers file. If the ftpusers file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the ftpusers file to root.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-708r2_chk'
  tag severity: 'medium'
  tag gid: 'V-842'
  tag rid: 'SV-842r2_rule'
  tag stig_id: 'GEN004920'
  tag gtitle: 'GEN004920'
  tag fix_id: 'F-996r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
