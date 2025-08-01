control 'SV-35223' do
  title 'The /etc/smb.conf file must not have an extended ACL.'
  desc 'Excessive permissions could endanger the security of the Samba configuration file and, ultimately, the system and network.'
  desc 'check', "Check the group ownership of the Samba configuration file.
# find / -type f -name smb.conf | xargs -n1 ls -lL

If the permissions include a '+', the file has an extended ACL, this is a finding."
  desc 'fix', 'Remove the optional ACL from the file.
# chacl -z <path>/smb.conf'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-35067r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22497'
  tag rid: 'SV-35223r1_rule'
  tag stig_id: 'GEN006150'
  tag gtitle: 'GEN006150'
  tag fix_id: 'F-30354r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
