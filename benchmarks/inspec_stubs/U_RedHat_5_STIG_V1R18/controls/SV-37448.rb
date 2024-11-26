control 'SV-37448' do
  title 'The hosts.lpd (or equivalent) file must be owned by root, bin, sys, or lp.'
  desc 'Failure to give ownership of the hosts.lpd file to root, bin, sys, or lp provides the designated owner, and possible unauthorized users, with the potential to modify the hosts.lpd file.  Unauthorized modifications could disrupt access to local printers from authorized remote hosts or permit unauthorized remote access to local printers.'
  desc 'check', 'Check the ownership of the print service configuration file.

Procedure:
# ls -lL /etc/cups/printers.conf;

If no print service configuration file is found, this is not applicable.
If the owner of the file is not root, this is a finding'
  desc 'fix', 'Change the owner of the /etc/cups/printers.conf to root.

Procedure:
# chown root /etc/cups/printers.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36120r1_chk'
  tag severity: 'medium'
  tag gid: 'V-828'
  tag rid: 'SV-37448r1_rule'
  tag stig_id: 'GEN003920'
  tag gtitle: 'GEN003920'
  tag fix_id: 'F-31366r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
