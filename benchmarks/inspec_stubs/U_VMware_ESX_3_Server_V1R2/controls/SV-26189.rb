control 'SV-26189' do
  title 'The Datagram Congestion Control Protocol (DCCP) must be disabled unless required.'
  desc 'The Datagram Congestion Control Protocol (DCCP) is a proposed transport layer protocol. This protocol is not yet widely used. Binding this protocol to the network stack increases the attack surface of the host. Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'If there is no DCCP protocol handler for the system, this is not applicable.

Determine if the DCCP protocol handler is prevented from dynamic loading.  If it is not, this is a finding.'
  desc 'fix', 'Configure the system to not load the DCCP protocol handler dynamically.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29118r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22514'
  tag rid: 'SV-26189r1_rule'
  tag stig_id: 'GEN007080'
  tag gtitle: 'GEN007080'
  tag fix_id: 'F-26124r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
