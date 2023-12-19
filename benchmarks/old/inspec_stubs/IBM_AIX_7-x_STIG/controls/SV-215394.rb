control 'SV-215394' do
  title 'The Reliable Datagram Sockets (RDS) protocol must be disabled on AIX.'
  desc "The Reliable Datagram Sockets (RDS) protocol is a relatively new protocol developed by Oracle for communication between the nodes of a cluster. Binding this protocol to the network stack increases the attack surface of the host. Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.

AIX has RDS protocol installed as part of the 'bos.net.tcp.client' fileset. The RDS protocol in primarily used for communication on INFI-Band interfaces. The protocol is manually loaded with the bypassctrl command.

To prevent possible attacks this protocol must be disabled unless required."
  desc 'check', 'Determine if RDS is currently loaded:
# genkex | grep rds 

If there is any output from the command, this is a finding.'
  desc 'fix', 'Configure the system to not automatically load the RDS protocol handler. 

Check startup scripts for "bypasscrtl load rds" and comment out the "bypassctrl" commands.

Unload the driver from the kernel: 
# bypassctrl unload rds'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16592r294633_chk'
  tag severity: 'medium'
  tag gid: 'V-215394'
  tag rid: 'SV-215394r508663_rule'
  tag stig_id: 'AIX7-00-003089'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-16590r294634_fix'
  tag 'documentable'
  tag legacy: ['SV-101517', 'V-91419']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
