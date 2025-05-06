control 'SV-39890' do
  title 'The smb.conf file must be group-owned by root, bin, or sys.'
  desc 'If the group owner of the smb.conf file is not root or a system group, the file may be maliciously modified and the Samba configuration could be compromised.'
  desc 'fix', 'Change the group owner of the smb.conf file.

Procedure:

# chgrp root /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-1056'
  tag rid: 'SV-39890r3_rule'
  tag stig_id: 'GEN006120'
  tag gtitle: 'GEN006120'
  tag fix_id: 'F-34290r4_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
