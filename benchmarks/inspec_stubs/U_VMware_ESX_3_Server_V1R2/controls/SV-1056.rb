control 'SV-1056' do
  title 'The /etc/smb.conf file must be group-owned by root, bin, or sys.'
  desc 'If the group owner of the smb.conf file is not root or a system group, the file may be maliciously modified and the Samba configuration could be compromised.'
  desc 'check', 'Check the group ownership of the smb.conf file.

Procedure:
# find / -name /etc/samba/smb.conf
# ls -l <smb.conf file>

If an smb.conf file is not group-owned by root, bin, or sys, this is a finding'
  desc 'fix', 'Change the group owner of the smb.conf file.

Procedure:
# chgrp root smb.conf'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-28772r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1056'
  tag rid: 'SV-1056r2_rule'
  tag stig_id: 'GEN006120'
  tag gtitle: 'GEN006120'
  tag fix_id: 'F-1210r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
