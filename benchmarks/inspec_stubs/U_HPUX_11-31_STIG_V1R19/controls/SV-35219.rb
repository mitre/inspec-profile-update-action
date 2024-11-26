control 'SV-35219' do
  title 'The /etc/smb.conf file must be group-owned by root, bin, sys, or system.'
  desc 'If the group-owner of the smb.conf file is not root or a system group, the file may be maliciously modified and the Samba configuration could be compromised.'
  desc 'check', 'Check the group ownership of the smb.conf file.
# find / -type f -name smb.conf | xargs -n1 ls -lL

If the smb.conf file is not group-owned by root, bin, sys or other, this is a finding.'
  desc 'fix', 'Change the group owner of the "smb.conf" file.
# chgrp root /etc/samba/smb.conf'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-35063r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1056'
  tag rid: 'SV-35219r1_rule'
  tag stig_id: 'GEN006120'
  tag gtitle: 'GEN006120'
  tag fix_id: 'F-30350r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
