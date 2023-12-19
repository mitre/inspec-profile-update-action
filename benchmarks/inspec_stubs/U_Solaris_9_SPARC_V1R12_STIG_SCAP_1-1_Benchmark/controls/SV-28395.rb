control 'SV-28395' do
  title 'The traceroute command must be group-owned by sys, bin, or root.'
  desc "If the group owner of the traceroute command has not been set to a system group, unauthorized users could have access to the command and use it to gain information regarding a network's topology inside of the firewall.  This information may allow an attacker to determine trusted routers and other network information possibly leading to system and network compromise."
  desc 'fix', 'Change the group-owner of the traceroute command to root.

Procedure:
# chgrp root /usr/sbin/traceroute'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-4370'
  tag rid: 'SV-28395r1_rule'
  tag stig_id: 'GEN003980'
  tag gtitle: 'GEN003980'
  tag fix_id: 'F-25667r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
