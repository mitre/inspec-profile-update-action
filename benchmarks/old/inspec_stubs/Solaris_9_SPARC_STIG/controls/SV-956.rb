control 'SV-956' do
  title 'The /usr/aset/userlist file must be owned by root.'
  desc 'If the userlist file is not owned by root, then an unauthorized user can modify the file and enter an unauthorized user.'
  desc 'fix', 'Use the chmod command to change the owner of the /usr/aset/userlist file.  

# chown root /usr/aset/userlist'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-956'
  tag rid: 'SV-956r2_rule'
  tag stig_id: 'GEN000000-SOL00240'
  tag gtitle: 'GEN000000-SOL00240'
  tag fix_id: 'F-1110r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
