control 'SV-26219' do
  title 'Proxy Neighbor Discovery Protocol (NDP) must not be enabled on the system.'
  desc 'Proxy Neighbor Discovery Protocol (NDP) allows a system to respond to NDP requests on one interface on behalf of hosts connected to another interface. If this function is enabled when not required, addressing information may be leaked between the attached network segments.'
  desc 'check', 'If the system does not support proxy NDP, this is not applicable.
Determine if the system has proxy NDP enabled.  If so, this is a finding.'
  desc 'fix', 'Disable proxy NDP on the system.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29300r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22544'
  tag rid: 'SV-26219r1_rule'
  tag stig_id: 'GEN007760'
  tag gtitle: 'GEN007760'
  tag fix_id: 'F-26332r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
