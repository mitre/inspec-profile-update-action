control 'SV-220043' do
  title 'The hosts.lpd (or equivalent) file must be group-owned by root, bin, or sys.'
  desc 'Failure to give group ownership of the hosts.lpd (or equivalent) file to root, bin, sys, or system provides the members of the owning group and possible unauthorized users, with the potential to modify it.  Unauthorized modifications could disrupt access to local printers from authorized remote hosts or permit unauthorized remote access to local printers.'
  desc 'check', 'Check the group ownership of the print service configuration files.

Procedure:

# ls -lL /etc/printers.conf /etc/apache/httpd-standalone-ipp.conf /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf

If the files are not group-owned by root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group owner of the print service configuration files. 
Procedure:

# chgrp bin /etc/apache/httpd-standalone-ipp.conf
# chgrp root /etc/printers.conf /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-21752r485073_chk'
  tag severity: 'medium'
  tag gid: 'V-220043'
  tag rid: 'SV-220043r603265_rule'
  tag stig_id: 'GEN003930'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21751r485074_fix'
  tag 'documentable'
  tag legacy: ['V-22435', 'SV-37456']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
