control 'SV-4371' do
  title 'The traceroute file must have mode 0700 or less permissive.'
  desc 'If the mode of the traceroute executable is more permissive than 0700, malicious code could be inserted by an attacker and triggered whenever the traceroute command is executed by authorized users.  Additionally, if an unauthorized user is granted executable permissions to the traceroute command, it could be used to gain information about the network topology behind the firewall.  This information may allow an attacker to determine trusted routers and other network information that may lead to system and network compromise.'
  desc 'check', 'Determine traceroute command locations and mode.
# find / -name traceroute -exec ls -lL {} \\;
If the traceroute command has a mode more permissive than 0700, this is a finding.'
  desc 'fix', 'Change the mode of the traceroute command.
# chmod 0700 <traceroute command>'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-8252r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4371'
  tag rid: 'SV-4371r2_rule'
  tag stig_id: 'GEN004000'
  tag gtitle: 'GEN004000'
  tag fix_id: 'F-4282r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
