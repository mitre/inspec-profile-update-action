control 'SV-26173' do
  title 'The /etc/smbpasswd file must not have an extended ACL.'
  desc 'If the permissions of the smbpasswd file are too permissive, the smbpasswd file may be maliciously accessed or modified, potentially resulting in the compromise of Samba accounts.'
  desc 'check', 'Check the group ownership of the Samba configuration file.
# ls -lL /etc/smbpasswd
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the /etc/smbpasswd file.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27809r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22498'
  tag rid: 'SV-26173r1_rule'
  tag stig_id: 'GEN006210'
  tag gtitle: 'GEN006210'
  tag fix_id: 'F-26307r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
