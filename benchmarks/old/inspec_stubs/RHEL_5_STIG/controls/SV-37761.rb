control 'SV-37761' do
  title 'The Stream Control Transmission Protocol (SCTP) must be disabled unless required.'
  desc 'The Stream Control Transmission Protocol (SCTP) is an Internet Engineering Task Force (IETF)-standardized transport layer protocol.  This protocol is not yet widely used.  Binding this protocol to the network stack increases the attack surface of the host.  Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'fix', 'Prevent the SCTP protocol handler for dynamic loading.
# echo "install sctp /bin/true" >> /etc/modprobe.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22511'
  tag rid: 'SV-37761r1_rule'
  tag stig_id: 'GEN007020'
  tag gtitle: 'GEN007020'
  tag fix_id: 'F-32222r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
