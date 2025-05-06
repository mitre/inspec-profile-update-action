control 'SV-37449' do
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
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36121r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22435'
  tag rid: 'SV-37449r2_rule'
  tag stig_id: 'GEN003930'
  tag gtitle: 'GEN003930'
  tag fix_id: 'F-31367r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
