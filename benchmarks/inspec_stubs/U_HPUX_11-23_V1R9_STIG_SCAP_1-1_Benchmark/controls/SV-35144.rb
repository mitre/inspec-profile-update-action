control 'SV-35144' do
  title 'The hosts.lpd (or equivalent) file must be group-owned by root, bin, sys, or system.'
  desc 'Failure to give group-ownership of  the hosts.lpd file to root, bin, sys, or system provides the members of the owning group and possible unauthorized users, with the potential to modify the hosts.lpd file.  Unauthorized modifications could disrupt access to local printers from authorized remote hosts or permit unauthorized remote access to local printers.'
  desc 'fix', 'Change the group-owner of the hosts.lpd (or equivalent) file(s).
# chgrp root /etc/hosts.lpd'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
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
