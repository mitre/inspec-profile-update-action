control 'SV-26216' do
  title 'The IPv6 protocol handler must not be bound to the network stack unless needed.'
  desc 'IPv6 is the next version of the Internet protocol.  Binding this protocol to the network stack increases the attack surface of the host.'
  desc 'check', 'If the IPv6 protocol handler is bound to the network stack, and the system does not need IPv6, this is a finding.'
  desc 'fix', 'Unbind the IPv6 protocol handler from the network stack.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29296r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22541'
  tag rid: 'SV-26216r1_rule'
  tag stig_id: 'GEN007700'
  tag gtitle: 'GEN007700'
  tag fix_id: 'F-26328r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
