control 'SV-26220' do
  title 'The system must not have 6to4 enabled.'
  desc '6to4 is an IPv6 transition mechanism that involves tunneling IPv6 packets encapsulated in IPv4 packets on an ad-hoc basis.  This is not a preferred transition strategy and increases the attack surface of the system.'
  desc 'check', 'Determine if there are any 6to4 tunnels configured on the system.  If any exist, this is a finding.'
  desc 'fix', 'Remove the configuration for any 6to4 tunnels on the system.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29301r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22545'
  tag rid: 'SV-26220r1_rule'
  tag stig_id: 'GEN007780'
  tag gtitle: 'GEN007780'
  tag fix_id: 'F-26333r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
