control 'SV-45822' do
  title 'The traceroute file must have mode 0700 or less permissive.'
  desc 'If the mode of the traceroute executable is more permissive than 0700, malicious code could be inserted by an attacker and triggered whenever the traceroute command is executed by authorized users.  Additionally, if an unauthorized user is granted executable permissions to the traceroute command, it could be used to gain information about the network topology behind the firewall.  This information may allow an attacker to determine trusted routers and other network information potentially leading to system and network compromise.'
  desc 'check', '# ls -lL /usr/sbin/traceroute


If the traceroute command has a mode more permissive than 0700, this is a finding.'
  desc 'fix', 'Change the mode of the traceroute command.
# chmod 0700 /usr/sbin/traceroute'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43141r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4371'
  tag rid: 'SV-45822r1_rule'
  tag stig_id: 'GEN004000'
  tag gtitle: 'GEN004000'
  tag fix_id: 'F-39209r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
