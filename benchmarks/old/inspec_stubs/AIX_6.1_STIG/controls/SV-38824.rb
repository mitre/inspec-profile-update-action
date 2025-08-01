control 'SV-38824' do
  title 'The /usr/lib/smb.conf file must not have an extended ACL.'
  desc 'Excessive permissions could endanger the security of the Samba configuration file and, ultimately, the system and network.'
  desc 'check', 'Check the group ownership of the Samba configuration file.
# aclget /usr/lib/smb.conf

If the extended attributes are not disabled, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the /usr/lib/smb.conf file and change extended attributes to disabled.

#acledit /usr/lib/smb.conf'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37071r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22497'
  tag rid: 'SV-38824r1_rule'
  tag stig_id: 'GEN006150'
  tag gtitle: 'GEN006150'
  tag fix_id: 'F-32340r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
