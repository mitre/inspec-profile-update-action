control 'SV-35248' do
  title 'The Reliable Datagram Sockets (RDS) protocol must be disabled or not installed unless required.'
  desc 'The Reliable Datagram Sockets (RDS) protocol is a relatively new protocol developed by Oracle for communication between the nodes of a cluster.  Binding this protocol to the network stack increases the attack surface of the host.  Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'If there is no RDS protocol handler for the system, this is not applicable.

The RDS protocol is not currently available for the HP-UX 11i platform and is therefore not applicable.'
  desc 'fix', 'Configure the system to not dynamically load the RDS protocol handler.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-35111r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22530'
  tag rid: 'SV-35248r1_rule'
  tag stig_id: 'GEN007480'
  tag gtitle: 'GEN007480'
  tag fix_id: 'F-26137r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
