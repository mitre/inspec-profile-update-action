control 'SV-37604' do
  title 'The Transparent Inter-Process Communication (TIPC) protocol must be disabled or uninstalled.'
  desc 'The TIPC protocol is a relatively new cluster communications protocol developed by Ericsson.  Binding this protocol to the network stack increases the attack surface of the host.   Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'fix', 'Prevent the TIPC protocol handler for dynamic loading.
# echo "install tipc /bin/true" >> /etc/modprobe.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22533'
  tag rid: 'SV-37604r1_rule'
  tag stig_id: 'GEN007540'
  tag gtitle: 'GEN007540'
  tag fix_id: 'F-31639r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
