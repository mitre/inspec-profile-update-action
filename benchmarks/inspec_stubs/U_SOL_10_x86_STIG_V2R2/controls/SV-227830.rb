control 'SV-227830' do
  title 'The hosts.lpd (or equivalent) must have mode 0644 or less permissive.'
  desc 'Excessive permissions on the hosts.lpd (or equivalent) file may permit unauthorized modification.  Unauthorized modifications could disrupt access to local printers from authorized remote hosts or permit unauthorized remote access to local printers.'
  desc 'check', 'Check the mode of the print service configuration files.

Procedure:

# ls -lL /etc/apache/httpd-standalone-ipp.conf /etc/printers.conf /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf

If the mode of any of the print service configuration file is more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of the print service configuration files to 0644 or less permissive.

Procedure:

# chmod 0644 /etc/apache/httpd-standalone-ipp.conf /etc/printers.conf /etc/smb.conf /etc/sfw/smb.conf /etc/samba/smb.conf /etc/sfw/samba/smb.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29992r489862_chk'
  tag severity: 'medium'
  tag gid: 'V-227830'
  tag rid: 'SV-227830r603266_rule'
  tag stig_id: 'GEN003940'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29980r489863_fix'
  tag 'documentable'
  tag legacy: ['V-829', 'SV-37457']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
