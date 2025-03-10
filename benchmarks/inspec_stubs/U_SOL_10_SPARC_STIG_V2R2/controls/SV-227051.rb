control 'SV-227051' do
  title 'The Transparent Inter-Process Communication (TIPC) protocol must be disabled or not installed.'
  desc 'The Transparent Inter-Process Communication (TIPC) protocol is a relatively new cluster communications protocol developed by Ericsson.  Binding this protocol to the network stack increases the attack surface of the host.   Unprivileged local processes may be able to cause the kernel to dynamically load a protocol handler by opening a socket using the protocol.

'
  desc 'check', 'Verify the TIPC protocol handler package is not installed.
# pkginfo | grep SUNWtipc
If the TIPC protocol handler package is not installed,  this is not a finding

Verify the TIPC protocol handler is prevented from dynamic loading.
# grep "exclude: tipc" /etc/system
If no result is returned, this is a finding.'
  desc 'fix', 'Remove the TIPC protocol handler package.
# pkgrm SUNWtipc

OR

Prevent the TIPC protocol handler from dynamic loading.
# echo "exclude: tipc" >> /etc/system'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29213r485522_chk'
  tag severity: 'medium'
  tag gid: 'V-227051'
  tag rid: 'SV-227051r603265_rule'
  tag stig_id: 'GEN007540'
  tag gtitle: 'SRG-OS-000096'
  tag fix_id: 'F-29201r485523_fix'
  tag satisfies: ['SRG-OS-000096', 'SRG-OS-000510']
  tag 'documentable'
  tag legacy: ['V-22533', 'SV-26902']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
