control 'SV-29601' do
  title 'Proxy Neighbor Discovery Protocol (NDP) must not be enabled on the system.'
  desc 'Proxy Neighbor Discovery Protocol (NDP) allows a system to respond to NDP requests on one interface on behalf of hosts connected to another interface. If this function is enabled when not required, addressing information may be leaked between the attached network segments.'
  desc 'check', 'Determine if any non-local published NDP entries exist on the system.
# ndp -a

If any NDP entries contain a flag of P, they are non-local published entries, and this is a finding.'
  desc 'fix', 'Remove non-local published NDP entries from the system.
# ndp -d <host>

Check system startup scripts for commands publishing NDP entries (such as "ndp -s <int> <host> <hwaddr> pub") and remove them.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-35083r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22544'
  tag rid: 'SV-29601r1_rule'
  tag stig_id: 'GEN007760'
  tag gtitle: 'GEN007760'
  tag fix_id: 'F-32129r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
