control 'SV-226926' do
  title 'The traceroute command must be group-owned by sys, bin, or root.'
  desc "If the group owner of the traceroute command has not been set to a system group, unauthorized users could have access to the command and use it to gain information regarding a network's topology inside of the firewall.  This information may allow an attacker to determine trusted routers and other network information possibly leading to system and network compromise."
  desc 'check', 'Check the group ownership of the traceroute file.

Procedure:
# ls -lL /usr/sbin/traceroute

If the traceroute command is not group-owned by root, sys, or bin, this is a finding.'
  desc 'fix', 'Change the group-owner of the traceroute command to root.

Procedure:
# chgrp root /usr/sbin/traceroute'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29088r485084_chk'
  tag severity: 'medium'
  tag gid: 'V-226926'
  tag rid: 'SV-226926r603265_rule'
  tag stig_id: 'GEN003980'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29076r485085_fix'
  tag 'documentable'
  tag legacy: ['V-4370', 'SV-28395']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
