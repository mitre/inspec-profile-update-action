control 'SV-218642' do
  title 'The /etc/smb.conf file must not have an extended ACL.'
  desc 'Excessive permissions could endanger the security of the Samba configuration file and, ultimately, the system and network.'
  desc 'check', "Check the permissions of the Samba configuration file.
# ls -lL /etc/samba/smb.conf
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/samba/smb.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20117r556124_chk'
  tag severity: 'medium'
  tag gid: 'V-218642'
  tag rid: 'SV-218642r603259_rule'
  tag stig_id: 'GEN006150'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20115r556125_fix'
  tag 'documentable'
  tag legacy: ['V-22497', 'SV-64085']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
