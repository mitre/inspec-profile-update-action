control 'SV-227831' do
  title 'The hosts.lpd (or equivalent) file must not have an extended ACL.'
  desc 'Excessive permissions on the hosts.lpd (or equivalent) file may permit unauthorized modification.  Unauthorized modifications could disrupt access to local printers from authorized remote hosts or permit unauthorized remote access to local printers.'
  desc 'check', "Check the permissions of the print service configuration files.

Procedure:
# ls -lL /etc/apache/httpd-standalone-ipp.conf /etc/printers.conf /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf

If the permissions on any file include a '+', the file has an extended ACL and this is a finding."
  desc 'fix', 'Remove the extended ACLs from the files.
# chmod A- /etc/apache/httpd-standalone-ipp.conf /etc/printers.conf /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29993r489865_chk'
  tag severity: 'medium'
  tag gid: 'V-227831'
  tag rid: 'SV-227831r603266_rule'
  tag stig_id: 'GEN003950'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29981r489866_fix'
  tag 'documentable'
  tag legacy: ['V-22436', 'SV-26678']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
