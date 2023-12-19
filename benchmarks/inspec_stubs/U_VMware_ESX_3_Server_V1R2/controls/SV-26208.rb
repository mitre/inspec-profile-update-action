control 'SV-26208' do
  title 'The Transparent Inter-Process Communication (TIPC) protocol must be disabled or uninstalled.'
  desc 'The Transparent Inter-Process Communication (TIPC) protocol is a relatively new cluster communications protocol developed by Ericsson.  Binding this protocol to the network stack increases the attack surface of the host.   Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'If there is no TIPC protocol handler for the system, this is not applicable.

Determine if the TIPC protocol handler is prevented from dynamic loading. If it is not, this is a finding.'
  desc 'fix', 'Configure the system to not dynamically load the TIPC protocol handler.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29133r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22533'
  tag rid: 'SV-26208r1_rule'
  tag stig_id: 'GEN007540'
  tag gtitle: 'GEN007540'
  tag fix_id: 'F-26139r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
