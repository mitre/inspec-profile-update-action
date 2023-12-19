control 'SV-38928' do
  title 'The /var/private/smbpasswd file must not have an extended ACL.'
  desc 'If the permissions of the smbpasswd file are too permissive, the smbpasswd file may be maliciously accessed or modified, potentially resulting in the compromise of Samba accounts.'
  desc 'check', 'Check the group ownership of the Samba configuration file.
# aclget /var/private/smbpasswd
If the extended attributes are not disabled, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the /var/private/smbpasswd file.  

# acledit /var/private/smbpasswd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37072r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22498'
  tag rid: 'SV-38928r1_rule'
  tag stig_id: 'GEN006210'
  tag gtitle: 'GEN006210'
  tag fix_id: 'F-33486r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
