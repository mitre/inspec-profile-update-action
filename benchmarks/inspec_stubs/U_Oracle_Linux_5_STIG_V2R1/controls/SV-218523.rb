control 'SV-218523' do
  title 'The hosts.lpd (or equivalent) file must be group-owned by lp.'
  desc 'Failure to give group-ownership of  the hosts.lpd file to root, bin, sys, or system provides the members of the owning group and possible unauthorized users, with the potential to modify the hosts.lpd file.  Unauthorized modifications could disrupt access to local printers from authorized remote hosts or permit unauthorized remote access to local printers.'
  desc 'check', 'Check the group ownership of the /etc/cups/printers.conf file.

Procedure:
# ls -lL /etc/cups/printers.conf

If the file is not group-owned by lp, this is a finding.'
  desc 'fix', 'Change the group-owner of the printers.conf file.

Procedure:
# chgrp lp /etc/cups/printers.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19998r562690_chk'
  tag severity: 'medium'
  tag gid: 'V-218523'
  tag rid: 'SV-218523r603259_rule'
  tag stig_id: 'GEN003930'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19996r562691_fix'
  tag 'documentable'
  tag legacy: ['V-22435', 'SV-64117']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
