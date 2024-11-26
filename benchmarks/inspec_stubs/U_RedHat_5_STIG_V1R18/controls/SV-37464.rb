control 'SV-37464' do
  title 'The traceroute command must be group-owned by sys, bin, root, or system.'
  desc "If the group owner of the traceroute command has not been set to a system group, unauthorized users could have access to the command and use it to gain information regarding a network's topology inside of the firewall.  This information may allow an attacker to determine trusted routers and other network information potentially leading to system and network compromise."
  desc 'check', 'Check the group ownership of the traceroute file.

Procedure:
# ls -lL /bin/traceroute

If the traceroute command is not group-owned by root, sys, bin, or system, this is a finding.'
  desc 'fix', 'Change the group-owner of the traceroute command to root.

Procedure:
# chgrp root /bin/traceroute'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36130r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4370'
  tag rid: 'SV-37464r1_rule'
  tag stig_id: 'GEN003980'
  tag gtitle: 'GEN003980'
  tag fix_id: 'F-31375r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
