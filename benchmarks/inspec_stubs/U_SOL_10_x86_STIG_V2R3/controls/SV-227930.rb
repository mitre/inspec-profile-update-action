control 'SV-227930' do
  title 'The smbpasswd file must be group-owned by root.'
  desc 'If the smbpasswd file is not group-owned by root, the smbpasswd file may be maliciously accessed or modified, potentially resulting in the compromise of Samba accounts.'
  desc 'check', 'Check smbpasswd ownership.

# ls -lL /etc/sfw/private/smbpasswd

If smbpasswd is not group-owned by root, this is a finding.'
  desc 'fix', 'Use the chgrp command to ensure the group owner of the smbpasswd file is root.

# chgrp root /etc/sfw/private/smbpasswd'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30092r490210_chk'
  tag severity: 'medium'
  tag gid: 'V-227930'
  tag rid: 'SV-227930r603266_rule'
  tag stig_id: 'GEN006180'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30080r490211_fix'
  tag 'documentable'
  tag legacy: ['V-1058', 'SV-40287']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
