control 'SV-28397' do
  title 'The traceroute command must be group-owned by sys, bin, or system.'
  desc "If the group owner of the traceroute command has not been set to a system group, unauthorized users could have access to the command and use it to gain information regarding a network's topology inside of the firewall.  This information may allow an attacker to determine trusted routers and other network information possibly leading to system and network compromise."
  desc 'check', 'Check the group ownership of the traceroute file.

Procedure:
# ls -lL /usr/bin/traceroute

If the traceroute command is not group-owned by sys, bin, or system, this is a finding.'
  desc 'fix', 'Change the group owner of the traceroute command to sys, bin, or system.

Procedure:
# chgrp system /usr/bin/traceroute'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28633r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4370'
  tag rid: 'SV-28397r1_rule'
  tag stig_id: 'GEN003980'
  tag gtitle: 'GEN003980'
  tag fix_id: 'F-25668r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
