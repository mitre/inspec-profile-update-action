control 'SV-28393' do
  title 'The traceroute command owner must be root.'
  desc 'If the traceroute command owner has not been set to root, an unauthorized user could use this command to obtain knowledge of the network topology inside the firewall.  This information may allow an attacker to determine trusted routers and other network information possibly leading to system and network compromise.'
  desc 'check', '# ls -lL /usr/bin/traceroute
If the traceroute command is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the traceroute command to root.
Example:
# chown root /usr/bin/traceroute'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28630r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4369'
  tag rid: 'SV-28393r1_rule'
  tag stig_id: 'GEN003960'
  tag gtitle: 'GEN003960'
  tag fix_id: 'F-25665r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
