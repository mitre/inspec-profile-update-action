control 'SV-226950' do
  title 'The ftpusers file must be owned by root.'
  desc 'If the file ftpusers is not owned by root, an unauthorized user may modify the file to allow unauthorized accounts to use FTP.'
  desc 'check', 'Check the ownership of the ftpusers file.
# ls -l /etc/ftpd/ftpusers
If the ftpusers file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the ftpusers file to root.
# chown root /etc/ftpd/ftpusers'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29112r485177_chk'
  tag severity: 'medium'
  tag gid: 'V-226950'
  tag rid: 'SV-226950r603265_rule'
  tag stig_id: 'GEN004920'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29100r485178_fix'
  tag 'documentable'
  tag legacy: ['V-842', 'SV-28410']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
