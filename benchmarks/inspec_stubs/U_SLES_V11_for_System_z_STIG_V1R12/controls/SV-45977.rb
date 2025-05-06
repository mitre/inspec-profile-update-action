control 'SV-45977' do
  title 'The Transparent Inter-Process Communication (TIPC) protocol must be disabled or uninstalled.'
  desc 'The TIPC protocol is a relatively new cluster communications protocol developed by Ericsson.  Binding this protocol to the network stack increases the attack surface of the host.   Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', "Verify the TIPC protocol handler is prevented from dynamic loading.
# grep 'install tipc' /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/* | grep ‘/bin/true’

If no result is returned, this is a finding."
  desc 'fix', 'Prevent the TIPC protocol handler for dynamic loading.
# echo "install tipc /bin/true" >> /etc/modprobe.conf.local'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43259r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22533'
  tag rid: 'SV-45977r1_rule'
  tag stig_id: 'GEN007540'
  tag gtitle: 'GEN007540'
  tag fix_id: 'F-39342r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
