control 'SV-218639' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20114r556115_chk'
  tag severity: 'medium'
  tag gid: 'V-218639'
  tag rid: 'SV-218639r603259_rule'
  tag stig_id: 'GEN006100'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20112r556116_fix'
  tag 'documentable'
  tag legacy: ['V-1027', 'SV-64095']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end
