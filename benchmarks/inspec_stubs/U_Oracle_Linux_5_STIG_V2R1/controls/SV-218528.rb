control 'SV-218528' do
  title 'The traceroute file must have mode 0700 or less permissive.'
  desc 'If the mode of the traceroute executable is more permissive than 0700, malicious code could be inserted by an attacker and triggered whenever the traceroute command is executed by authorized users.  Additionally, if an unauthorized user is granted executable permissions to the traceroute command, it could be used to gain information about the network topology behind the firewall.  This information may allow an attacker to determine trusted routers and other network information potentially leading to system and network compromise.'
  desc 'check', '# ls -lL /bin/traceroute
If the traceroute command has a mode more permissive than 0700, this is a finding.'
  desc 'fix', 'Change the mode of the traceroute command.
# chmod 0700 /bin/traceroute'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20003r562705_chk'
  tag severity: 'medium'
  tag gid: 'V-218528'
  tag rid: 'SV-218528r603259_rule'
  tag stig_id: 'GEN004000'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-20001r562706_fix'
  tag 'documentable'
  tag legacy: ['V-4371', 'SV-63525']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
