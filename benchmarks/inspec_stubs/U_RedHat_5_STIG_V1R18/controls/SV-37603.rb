control 'SV-37603' do
  title 'The Reliable Datagram Sockets (RDS) protocol must be disabled or not installed unless required.'
  desc 'The RDS protocol is a relatively new protocol developed by Oracle for communication between the nodes of a cluster.  Binding this protocol to the network stack increases the attack surface of the host.  Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', "Ask the SA if RDS is required by application software running on the system. If so, this is not applicable.

Verify the RDS protocol handler is prevented from dynamic loading.
# grep 'install rds /bin/true' /etc/modprobe.conf /etc/modprobe.d/*
If no result is returned, this is a finding."
  desc 'fix', 'Prevent the RDS protocol handler for dynamic loading.
# echo "install rds /bin/true" >> /etc/modprobe.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36740r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22530'
  tag rid: 'SV-37603r1_rule'
  tag stig_id: 'GEN007480'
  tag gtitle: 'GEN007480'
  tag fix_id: 'F-31638r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
