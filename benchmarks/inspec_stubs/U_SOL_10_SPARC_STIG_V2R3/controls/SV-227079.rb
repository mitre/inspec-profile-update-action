control 'SV-227079' do
  title 'The hosts.lpd (or equivalent) file must be owned by root.'
  desc 'Failure to give ownership of the hosts.lpd file to root provides the designated owner, and possible unauthorized users, with the potential to modify the hosts.lpd file.  Unauthorized modifications could disrupt access to local printers from authorized remote hosts or permit unauthorized remote access to local printers.'
  desc 'check', 'Check the owner of the print service configuration files.
Procedure:

# ls -lL /etc/apache/httpd-standalone-ipp.conf /etc/printers.conf /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf

If the owner of any of the print service configuration files is not root, this is a finding.'
  desc 'fix', 'Change the owner of the print service configuration files.
Procedure:

# chown root /etc/apache/httpd-standalone-ipp.conf /etc/printers.conf /etc/sfw/smb.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29241r485624_chk'
  tag severity: 'medium'
  tag gid: 'V-227079'
  tag rid: 'SV-227079r854456_rule'
  tag stig_id: 'GEN003920'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29229r485625_fix'
  tag 'documentable'
  tag legacy: ['V-828', 'SV-37455']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
