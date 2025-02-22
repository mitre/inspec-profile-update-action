control 'SV-227019' do
  title 'The smb.conf file must be group-owned by root, bin, or sys.'
  desc 'If the group owner of the smb.conf file is not root or a system group, the file may be maliciously modified and the Samba configuration could be compromised.'
  desc 'check', 'Check the group ownership of the smb.conf file. Default locations for this file include /etc, /etc/sfw, /etc/samba, and /etc/sfw/samba.  If the system has Samba installed in non-standard locations, also check the smb.conf in those locations.

Procedure:

# ls -l /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf

If an smb.conf file is not group-owned by root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group owner of the smb.conf file.

Procedure:

# chgrp root /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29181r485411_chk'
  tag severity: 'medium'
  tag gid: 'V-227019'
  tag rid: 'SV-227019r603265_rule'
  tag stig_id: 'GEN006120'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29169r485412_fix'
  tag 'documentable'
  tag legacy: ['SV-39890', 'V-1056']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
