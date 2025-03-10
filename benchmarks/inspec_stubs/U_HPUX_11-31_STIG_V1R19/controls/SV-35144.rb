control 'SV-35144' do
  title 'The hosts.lpd (or equivalent) file must be group-owned by root, bin, sys, or system.'
  desc 'Failure to give group-ownership of  the hosts.lpd file to root, bin, sys, or system provides the members of the owning group and possible unauthorized users, with the potential to modify the hosts.lpd file.  Unauthorized modifications could disrupt access to local printers from authorized remote hosts or permit unauthorized remote access to local printers.'
  desc 'check', 'When rlpdaemon is started by inetd, access control is provided via the file /var/adm/inetd.sec to allow or prevent a host from making requests.  When rlpdaemon is not started by inetd(1M), all requests  must come from one of the machines listed in the file /etc/hosts.equiv   or  /var/spool/lp/.rhosts.  When /var/spool/lp/.rhosts is used for access, the user name should be lp. Check the group ownership of the /etc/hosts.lpd (or equivalent) file(s).
# ls -lL /var/spool/lp/.rhosts
# ls -lL /var/adm/inetd.sec
# ls -lL /etc/hosts.equiv

If the file is not group-owned by root, bin, sys, or other, this is a finding.'
  desc 'fix', 'Change the group-owner of the hosts.lpd (or equivalent) file(s).
# chgrp root /etc/hosts.lpd'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36547r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22435'
  tag rid: 'SV-35144r1_rule'
  tag stig_id: 'GEN003930'
  tag gtitle: 'GEN003930'
  tag fix_id: 'F-31913r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
