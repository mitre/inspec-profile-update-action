control 'SV-227929' do
  title 'The smbpasswd file must be owned by root.'
  desc 'If the smbpasswd file is not owned by root, the smbpasswd file may be maliciously accessed or modified, potentially resulting in the compromise of Samba accounts.'
  desc 'check', 'Check the ownership of the smbpasswd file.

# ls -lL /etc/sfw/private/smbpasswd

If the smbpasswd file is not owned by root, this is a finding.'
  desc 'fix', 'Use the chown command to configure the smb passwd file.
# chown root /etc/sfw/private/smbpasswd'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30091r490207_chk'
  tag severity: 'medium'
  tag gid: 'V-227929'
  tag rid: 'SV-227929r603266_rule'
  tag stig_id: 'GEN006160'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30079r490208_fix'
  tag 'documentable'
  tag legacy: ['V-1029', 'SV-40284']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
