control 'SV-227022' do
  title 'The smbpasswd file must be owned by root.'
  desc 'If the smbpasswd file is not owned by root, the smbpasswd file may be maliciously accessed or modified, potentially resulting in the compromise of Samba accounts.'
  desc 'check', 'Check the ownership of the smbpasswd file.

# ls -lL /etc/sfw/private/smbpasswd

If the smbpasswd file is not owned by root, this is a finding.'
  desc 'fix', 'Use the chown command to configure the smb passwd file.
# chown root /etc/sfw/private/smbpasswd'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29184r485420_chk'
  tag severity: 'medium'
  tag gid: 'V-227022'
  tag rid: 'SV-227022r603265_rule'
  tag stig_id: 'GEN006160'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29172r485421_fix'
  tag 'documentable'
  tag legacy: ['V-1029', 'SV-40284']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
