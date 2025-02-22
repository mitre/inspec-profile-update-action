control 'SV-26172' do
  title 'The /etc/smb.conf file must not have an extended ACL.'
  desc 'Excessive permissions could endanger the security of the Samba configuration file and, ultimately, the system and network.'
  desc 'check', 'Check the group ownership of the Samba configuration file. Default locations for this file include /etc, /etc/sfw, /etc/samba, and /etc/sfw/samba.  If the system has Samba installed in non-standard locations, also check the smb.conf in those locations.

Procedure:

# ls -lL /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf

If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the /etc/smb.conf file.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27808r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22497'
  tag rid: 'SV-26172r1_rule'
  tag stig_id: 'GEN006150'
  tag gtitle: 'GEN006150'
  tag fix_id: 'F-26306r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
