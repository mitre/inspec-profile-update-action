control 'SV-38913' do
  title 'The Reliable Datagram Sockets (RDS) protocol must be disabled or not installed unless required.'
  desc 'The Reliable Datagram Sockets (RDS) protocol is a relatively new protocol developed by Oracle for communication between the nodes of a cluster.  Binding this protocol to the network stack increases the attack surface of the host.  Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', "AIX has RDS protocol installed as part of the 'bos.net.tcp.client' fileset.   The RDS protocol in primarily used for communication on INFI-Band interfaces.   The protocol is manually loaded with the bypassctrl command.

Determine if RDS is currently loaded.
#genkex | grep rds

If the RDS protocol is loaded, ask the SA if RDS is required by application software running on the system. If so, this is not applicable.

If the RDS protocol is loaded and the protocol is not used by application software,  this is a finding."
  desc 'fix', "Configure the system to not automatically load the RDS protocol handler.   

Check startup scripts for 'bypassctrl load rds' and comment out the bypassctrl  commands.

Unload the driver from the kernel.
# bypassctrl unload rds"
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37904r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22530'
  tag rid: 'SV-38913r1_rule'
  tag stig_id: 'GEN007480'
  tag gtitle: 'GEN007480'
  tag fix_id: 'F-33161r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
