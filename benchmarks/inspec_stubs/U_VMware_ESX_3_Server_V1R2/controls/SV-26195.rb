control 'SV-26195' do
  title 'The Internetwork Packet Exchange (IPX) protocol must be disabled or not installed.'
  desc 'The Internetwork Packet Exchange (IPX) protocol is a network-layer protocol that is no longer in common use.  Binding this protocol to the network stack increases the attack surface of the host.  Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'If there is no IPX protocol handler for the system, this is not applicable.

Determine if the IPX protocol handler is prevented from dynamic loading. If it is not, this is a finding.'
  desc 'fix', 'Configure the system to not dynamically load the IPX protocol handler.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29123r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22520'
  tag rid: 'SV-26195r1_rule'
  tag stig_id: 'GEN007200'
  tag gtitle: 'GEN007200'
  tag fix_id: 'F-26129r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
