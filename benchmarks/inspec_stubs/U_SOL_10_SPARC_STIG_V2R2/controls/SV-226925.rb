control 'SV-226925' do
  title 'The traceroute command owner must be root.'
  desc 'If the traceroute command owner has not been set to root, an unauthorized user could use this command to obtain knowledge of the network topology inside the firewall.  This information may allow an attacker to determine trusted routers and other network information possibly leading to system and network compromise.'
  desc 'check', '# ls -lL /usr/sbin/traceroute
If the traceroute command is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the traceroute command to root.
Example procedure:
# chown root /usr/sbin/traceroute'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29087r485081_chk'
  tag severity: 'medium'
  tag gid: 'V-226925'
  tag rid: 'SV-226925r603265_rule'
  tag stig_id: 'GEN003960'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29075r485082_fix'
  tag 'documentable'
  tag legacy: ['V-4369', 'SV-28392']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
