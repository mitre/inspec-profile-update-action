control 'SV-218640' do
  title 'The /etc/smb.conf file must be group-owned by root, bin, sys, or system.'
  desc 'If the group owner of the "smb.conf" file is not root or a system group, the file may be maliciously modified and the Samba configuration could be compromised.'
  desc 'check', 'Check the group ownership of the "smb.conf" file.

Procedure:
# ls -lL /etc/samba/smb.conf

If the "smb.conf" file is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group owner of the smb.conf file.

Procedure:
# chgrp root smb.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20115r556118_chk'
  tag severity: 'medium'
  tag gid: 'V-218640'
  tag rid: 'SV-218640r603259_rule'
  tag stig_id: 'GEN006120'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20113r556119_fix'
  tag 'documentable'
  tag legacy: ['V-1056', 'SV-64093']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
