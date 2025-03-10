control 'SV-1027' do
  title 'The /etc/smb.conf file must be owned by root.'
  desc 'The /etc/smb.conf file allows access to other machines on the network and grants permissions to certain users.  If it is owned by another user, the file may be maliciously modified and the Samba configuration could be compromised.'
  desc 'check', 'Check the ownership of the smb.conf file. Default locations for this file include /etc, /etc/sfw, /etc/samba, and /etc/sfw/samba.  If the system has Samba installed in non-standard locations, also check the smb.conf in those locations.

Procedure:

# ls -lL /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf
# ls -l /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf

If an smb.conf file is not owned by root, this is a finding.'
  desc 'fix', 'Change the ownership of the smb.conf file. 

Procedure:

# chown root /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-28771r4_chk'
  tag severity: 'medium'
  tag gid: 'V-1027'
  tag rid: 'SV-1027r3_rule'
  tag stig_id: 'GEN006100'
  tag gtitle: 'GEN006100'
  tag fix_id: 'F-1181r4_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
