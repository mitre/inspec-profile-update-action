control 'SV-37763' do
  title 'The Datagram Congestion Control Protocol (DCCP) must be disabled unless required.'
  desc 'The DCCP is a proposed transport layer protocol.  This protocol is not yet widely used.  Binding this protocol to the network stack increases the attack surface of the host.  Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'fix', 'Prevent the DCCP protocol handler for dynamic loading.
# echo "install dccp /bin/true" >> /etc/modprobe.conf
# echo "install dccp_ipv4 /bin/true" >> /etc/modprobe.conf
# echo "install dccp_ipv6 /bin/true" >> /etc/modprobe.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22514'
  tag rid: 'SV-37763r1_rule'
  tag stig_id: 'GEN007080'
  tag gtitle: 'GEN007080'
  tag fix_id: 'F-32223r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
