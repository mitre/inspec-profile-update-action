control 'SV-37871' do
  title 'The /etc/smb.conf file must be owned by root.'
  desc 'The /etc/smb.conf file allows access to other machines on the network and grants permissions to certain users.  If it is owned by another user, the file may be maliciously modified and the Samba configuration could be compromised.'
  desc 'fix', 'Change the ownership of the smb.conf file. 

Procedure:
# chown root smb.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-1027'
  tag rid: 'SV-37871r1_rule'
  tag stig_id: 'GEN006100'
  tag gtitle: 'GEN006100'
  tag fix_id: 'F-32360r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
