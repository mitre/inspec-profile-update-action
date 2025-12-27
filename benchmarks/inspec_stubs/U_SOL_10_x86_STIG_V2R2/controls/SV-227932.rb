control 'SV-227932' do
  title 'The smbpasswd file must not have an extended ACL.'
  desc 'If the permissions of the smbpasswd file are too permissive, the smbpasswd file may be maliciously accessed or modified, potentially resulting in the compromise of Samba accounts.'
  desc 'check', 'Check the group ownership of the Samba configuration file.
# ls -lL /etc/sfw/private/smbpasswd
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /etc/sfw/private/smbpasswd'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30094r490216_chk'
  tag severity: 'medium'
  tag gid: 'V-227932'
  tag rid: 'SV-227932r603266_rule'
  tag stig_id: 'GEN006210'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30082r490217_fix'
  tag 'documentable'
  tag legacy: ['V-22498', 'SV-26828']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
