control 'SV-227925' do
  title 'The smb.conf file must be owned by root.'
  desc 'The smb.conf file allows access to other machines on the network and grants permissions to certain users.  If it is owned by another user, the file may be maliciously modified and the Samba configuration could be compromised.'
  desc 'check', 'Check the ownership of the smb.conf file.  Default locations for this file include /etc, /etc/sfw, /etc/samba, and /etc/sfw/samba.  If the system has Samba installed in non-standard locations, also check the smb.conf in those locations.
 
Procedure:
# ls -l /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf
 
If a smb.conf file is not owned by root, this is a finding.'
  desc 'fix', 'Change the ownership of the smb.conf file.

Procedure:
# chown root /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30087r490195_chk'
  tag severity: 'medium'
  tag gid: 'V-227925'
  tag rid: 'SV-227925r603266_rule'
  tag stig_id: 'GEN006100'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30075r490196_fix'
  tag 'documentable'
  tag legacy: ['V-1027', 'SV-40291']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
