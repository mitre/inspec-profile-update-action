control 'SV-37877' do
  title 'The /etc/smb.conf file must not have an extended ACL.'
  desc 'Excessive permissions could endanger the security of the Samba configuration file and, ultimately, the system and network.'
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/samba/smb.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22497'
  tag rid: 'SV-37877r1_rule'
  tag stig_id: 'GEN006150'
  tag gtitle: 'GEN006150'
  tag fix_id: 'F-32372r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
