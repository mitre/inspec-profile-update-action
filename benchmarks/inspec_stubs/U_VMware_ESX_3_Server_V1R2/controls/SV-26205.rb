control 'SV-26205' do
  title 'The Reliable Datagram Sockets (RDS) protocol must be disabled or not installed unless required.'
  desc 'The Reliable Datagram Sockets (RDS) protocol is a relatively new protocol developed by Oracle for communication between the nodes of a cluster.  Binding this protocol to the network stack increases the attack surface of the host.  Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'If there is no RDS protocol handler for the system, this is not applicable.

Ask the SA if RDS is required by application software running on the system. If so, this is not applicable.

Determine if the RDS protocol handler is prevented from dynamic loading. If it is not, this is a finding.'
  desc 'fix', 'Configure the system to not dynamically load the RDS protocol handler.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29131r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22530'
  tag rid: 'SV-26205r1_rule'
  tag stig_id: 'GEN007480'
  tag gtitle: 'GEN007480'
  tag fix_id: 'F-26137r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
