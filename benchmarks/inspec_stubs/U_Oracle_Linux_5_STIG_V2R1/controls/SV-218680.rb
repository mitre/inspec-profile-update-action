control 'SV-218680' do
  title 'The Transparent Inter-Process Communication (TIPC) protocol must be disabled or uninstalled.'
  desc 'The TIPC protocol is a relatively new cluster communications protocol developed by Ericsson.  Binding this protocol to the network stack increases the attack surface of the host.   Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', "Verify the TIPC protocol handler is prevented from dynamic loading.
# grep 'install tipc /bin/true' /etc/modprobe.conf /etc/modprobe.d/*
If no result is returned, this is a finding."
  desc 'fix', 'Prevent the TIPC protocol handler for dynamic loading.
# echo "install tipc /bin/true" >> /etc/modprobe.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20155r556454_chk'
  tag severity: 'medium'
  tag gid: 'V-218680'
  tag rid: 'SV-218680r603259_rule'
  tag stig_id: 'GEN007540'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-20153r556455_fix'
  tag 'documentable'
  tag legacy: ['V-22533', 'SV-63449']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
