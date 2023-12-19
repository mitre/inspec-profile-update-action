control 'SV-218522' do
  title 'The hosts.lpd (or equivalent) file must be owned by root, bin, sys, or lp.'
  desc 'Failure to give ownership of the hosts.lpd file to root, bin, sys, or lp provides the designated owner, and possible unauthorized users, with the potential to modify the hosts.lpd file.  Unauthorized modifications could disrupt access to local printers from authorized remote hosts or permit unauthorized remote access to local printers.'
  desc 'check', 'Check the ownership of the print service configuration file.

Procedure:
# ls -lL /etc/cups/printers.conf;

If no print service configuration file is found, this is not applicable.
If the owner of the file is not root, this is a finding.'
  desc 'fix', 'Change the owner of the /etc/cups/printers.conf to root.

Procedure:
# chown root /etc/cups/printers.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19997r562687_chk'
  tag severity: 'medium'
  tag gid: 'V-218522'
  tag rid: 'SV-218522r603259_rule'
  tag stig_id: 'GEN003920'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19995r562688_fix'
  tag 'documentable'
  tag legacy: ['V-828', 'SV-64119']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
