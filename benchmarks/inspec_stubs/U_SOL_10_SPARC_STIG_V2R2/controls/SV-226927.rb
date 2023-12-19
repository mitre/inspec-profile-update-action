control 'SV-226927' do
  title 'The traceroute file must have mode 0700 or less permissive.'
  desc 'If the mode of the traceroute executable is more permissive than 0700, malicious code could be inserted by an attacker and triggered whenever the traceroute command is executed by authorized users.  Additionally, if an unauthorized user is granted executable permissions to the traceroute command, it could be used to gain information about the network topology behind the firewall.  This information may allow an attacker to determine trusted routers and other network information that may lead to system and network compromise.'
  desc 'check', '# ls -lL /usr/sbin/traceroute
If the traceroute command has a mode more permissive than 0700, this is a finding.'
  desc 'fix', 'Change the mode of the traceroute command.
# chmod 0700 /usr/sbin/traceroute'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29089r485087_chk'
  tag severity: 'medium'
  tag gid: 'V-226927'
  tag rid: 'SV-226927r603265_rule'
  tag stig_id: 'GEN004000'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29077r485088_fix'
  tag 'documentable'
  tag legacy: ['V-4371', 'SV-28399']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
