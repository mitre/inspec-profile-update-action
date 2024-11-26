control 'SV-39235' do
  title 'The /var/private/smbpasswd file must be group-owned by sys or system.'
  desc 'If the smbpasswd file is not group-owned by root, the smbpasswd file may be maliciously accessed or modified, potentially resulting in the compromise of Samba accounts.'
  desc 'check', 'Check smbpasswd ownership.

# ls -lL /var/private/smbpasswd

If smbpasswd is not group-owned by sys, or system,  this is a finding.'
  desc 'fix', 'Use the chgrp command to change  the group owner of the smbpasswd file to system. 

# chgrp system /var/private/smbpasswd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38209r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1058'
  tag rid: 'SV-39235r1_rule'
  tag stig_id: 'GEN006180'
  tag gtitle: 'GEN006180'
  tag fix_id: 'F-33485r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
