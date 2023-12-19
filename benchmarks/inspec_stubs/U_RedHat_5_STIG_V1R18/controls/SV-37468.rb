control 'SV-37468' do
  title 'The traceroute file must not have an extended ACL.'
  desc 'If an extended ACL exists on the traceroute executable file, it may provide unauthorized users with access to the file.  Malicious code could be inserted by an attacker and triggered whenever the traceroute command is executed by authorized users.  Additionally, if an unauthorized user is granted executable permissions to the traceroute command, it could be used to gain information about the network topology behind the firewall.  This information may allow an attacker to determine trusted routers and other network information potentially leading to system and network compromise.'
  desc 'check', "Check the permissions of the /bin/traceroute file.
# ls -lL /bin/traceroute
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /bin/traceroute'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36134r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22437'
  tag rid: 'SV-37468r1_rule'
  tag stig_id: 'GEN004010'
  tag gtitle: 'GEN004010'
  tag fix_id: 'F-31379r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
