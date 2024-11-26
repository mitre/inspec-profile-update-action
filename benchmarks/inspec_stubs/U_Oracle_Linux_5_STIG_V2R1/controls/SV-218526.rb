control 'SV-218526' do
  title 'The traceroute command owner must be root.'
  desc 'If the traceroute command owner has not been set to root, an unauthorized user could use this command to obtain knowledge of the network topology inside the firewall.  This information may allow an attacker to determine trusted routers and other network information potentially leading to system and network compromise.'
  desc 'check', '# ls -lL /bin/traceroute
If the traceroute command is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the traceroute command to root.
Example:
# chown root /bin/traceroute'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20001r562699_chk'
  tag severity: 'medium'
  tag gid: 'V-218526'
  tag rid: 'SV-218526r603259_rule'
  tag stig_id: 'GEN003960'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19999r562700_fix'
  tag 'documentable'
  tag legacy: ['V-4369', 'SV-63487']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
