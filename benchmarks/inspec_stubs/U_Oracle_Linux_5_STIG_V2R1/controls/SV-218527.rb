control 'SV-218527' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20002r562702_chk'
  tag severity: 'medium'
  tag gid: 'V-218527'
  tag rid: 'SV-218527r603259_rule'
  tag stig_id: 'GEN003980'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-20000r562703_fix'
  tag 'documentable'
  tag legacy: ['V-4370', 'SV-63511']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
