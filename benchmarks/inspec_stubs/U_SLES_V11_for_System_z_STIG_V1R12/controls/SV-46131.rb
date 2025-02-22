control 'SV-46131' do
  title 'The /etc/smb.conf file must be owned by root.'
  desc 'The /etc/smb.conf file allows access to other machines on the network and grants permissions to certain users.  If it is owned by another user, the file may be maliciously modified and the Samba configuration could be compromised.'
  desc 'check', 'Check the ownership of the /etc/samba/smb.conf file.

Procedure:
# ls -l /etc/samba/smb.conf
If an smb.conf file is not owned by root, this is a finding.'
  desc 'fix', 'Change the ownership of the smb.conf file. 

Procedure:
# chown root smb.conf'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43390r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1027'
  tag rid: 'SV-46131r1_rule'
  tag stig_id: 'GEN006100'
  tag gtitle: 'GEN006100'
  tag fix_id: 'F-39473r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
