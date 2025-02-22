control 'SV-39875' do
  title 'The hosts.lpd (or equivalent) file must be group-owned by bin, sys, or system.'
  desc 'Failure to give group ownership of  the hosts.lpd file to bin, sys, or system provides the members of the owning group and possible unauthorized users, with the potential to modify the hosts.lpd file.  Unauthorized modifications could disrupt access to local printers from authorized remote hosts or permit unauthorized remote access to local printers.'
  desc 'check', 'Check the group ownership of the /etc/hosts.lpd file.

Procedure:
# ls -lL /etc/hosts.lpd

If the file is not group owned by bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group owner of the hosts.lpd file.

Procedure:
# chgrp sys /etc/hosts.lpd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38878r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22435'
  tag rid: 'SV-39875r1_rule'
  tag stig_id: 'GEN003930'
  tag gtitle: 'GEN003930'
  tag fix_id: 'F-34022r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
