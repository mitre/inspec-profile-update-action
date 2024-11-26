control 'SV-218524' do
  title 'The hosts.lpd (or equivalent) must have mode 0644 or less permissive.'
  desc 'Excessive permissions on the hosts.lpd (or equivalent) file may permit unauthorized modification.  Unauthorized modifications could disrupt access to local printers from authorized remote hosts or permit unauthorized remote access to local printers.'
  desc 'check', 'Check the mode of the print service configuration file.

Procedure:
# ls -lL /etc/cups/printers.conf

If no print service configuration file is found, this is not applicable.
If the mode of the print service configuration file is more permissive than 0664, this is a finding.'
  desc 'fix', 'Change the mode of the /etc/cups/printers.conf file to 0664 or less permissive.

Procedure:
# chmod 0664 /etc/cups/printers.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19999r562693_chk'
  tag severity: 'medium'
  tag gid: 'V-218524'
  tag rid: 'SV-218524r603259_rule'
  tag stig_id: 'GEN003940'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19997r562694_fix'
  tag 'documentable'
  tag legacy: ['V-829', 'SV-64121']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
