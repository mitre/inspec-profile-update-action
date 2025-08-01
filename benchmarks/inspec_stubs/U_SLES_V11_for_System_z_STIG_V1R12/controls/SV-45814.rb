control 'SV-45814' do
  title 'The hosts.lpd (or equivalent) file must be group-owned by root, bin, sys, or system.'
  desc 'Failure to give group-ownership of  the hosts.lpd file to root, bin, sys, or system provides the members of the owning group and possible unauthorized users, with the potential to modify the hosts.lpd file.  Unauthorized modifications could disrupt access to local printers from authorized remote hosts or permit unauthorized remote access to local printers.'
  desc 'check', 'Check the group ownership of the /etc/hosts.lpd(or equivalent) file.

Procedure:
# ls -lL /etc/hosts.lpd

If the file is not group-owned by root, bin, sys, or system, this is a finding.
Check the group ownership of the /etc/cups/printers.conf file.


# ls -lL /etc/cups/printers.conf

If the file is not group-owned by lp, this is a finding.'
  desc 'fix', 'Change the group-owner of the hosts.lpd file.

Procedure:
# chgrp root /etc/hosts.lpd
Change the group-owner of the printers.conf file.


# chgrp lp /etc/cups/printers.conf'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43136r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22435'
  tag rid: 'SV-45814r1_rule'
  tag stig_id: 'GEN003930'
  tag gtitle: 'GEN003930'
  tag fix_id: 'F-39203r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
