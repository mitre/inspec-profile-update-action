control 'SV-1058' do
  title 'The /etc/smbpasswd file must be group-owned by root.'
  desc 'If the smbpasswd file is not group-owned by root, the smbpasswd file may be maliciously accessed or modified, potentially resulting in the compromise of Samba accounts.'
  desc 'check', 'Check smbpasswd ownership.

# find / -name smbpasswd
# ls -lL <smbpasswd file>

If smbpasswd is not group-owned by root, this is a finding.'
  desc 'fix', 'Use the chgrp command to ensure the group owner of the smbpasswd file is root. 

# chgrp root /etc/smbpasswd.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2051r2_chk'
  tag severity: 'medium'
  tag gid: 'V-1058'
  tag rid: 'SV-1058r2_rule'
  tag stig_id: 'GEN006180'
  tag gtitle: 'GEN006180'
  tag fix_id: 'F-1212r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
