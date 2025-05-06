control 'SV-226928' do
  title 'The traceroute file must not have an extended ACL.'
  desc 'If an extended ACL exists on the traceroute executable file, it may provide unauthorized users with access to the file.  Malicious code could be inserted by an attacker and triggered whenever the traceroute command is executed by authorized users.  Additionally, if an unauthorized user is granted executable permissions to the traceroute command, it could be used to gain information about the network topology behind the firewall.  This information may allow an attacker to determine trusted routers and other network information possibly leading to system and network compromise.'
  desc 'check', 'Check the permissions of the /usr/sbin/traceroute file.
# ls -lL /usr/contrib/bin/traceroute

If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /usr/sbin/traceroute'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29090r485090_chk'
  tag severity: 'medium'
  tag gid: 'V-226928'
  tag rid: 'SV-226928r603265_rule'
  tag stig_id: 'GEN004010'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29078r485091_fix'
  tag 'documentable'
  tag legacy: ['V-22437', 'SV-26682']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
