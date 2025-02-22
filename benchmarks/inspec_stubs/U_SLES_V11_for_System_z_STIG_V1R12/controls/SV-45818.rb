control 'SV-45818' do
  title 'The traceroute command owner must be root.'
  desc 'If the traceroute command owner has not been set to root, an unauthorized user could use this command to obtain knowledge of the network topology inside the firewall.  This information may allow an attacker to determine trusted routers and other network information potentially leading to system and network compromise.'
  desc 'check', '# ls -lL /usr/sbin/traceroute

If the traceroute command is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the traceroute command to root.
Example:
# chown root /usr/sbin/traceroute'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43139r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4369'
  tag rid: 'SV-45818r1_rule'
  tag stig_id: 'GEN003960'
  tag gtitle: 'GEN003960'
  tag fix_id: 'F-39206r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
