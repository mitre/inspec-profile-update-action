control 'SV-37880' do
  title 'The smbpasswd file must be group-owned by root.'
  desc 'If the smbpasswd file is not group-owned by root, it may be maliciously accessed or modified, potentially resulting in the compromise of Samba accounts.'
  desc 'check', 'Check smbpasswd ownership:
# ls -lL /var/opt/samba/private/smbpasswd

If the smbpasswd file is not group-owned by root, this is a finding.'
  desc 'fix', 'Use the chgrp command to ensure that the group owner of the smbpasswd file is root. 
# chgrp root <path>/smbpasswd'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-37107r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1058'
  tag rid: 'SV-37880r1_rule'
  tag stig_id: 'GEN006180'
  tag gtitle: 'GEN006180'
  tag fix_id: 'F-32374r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
