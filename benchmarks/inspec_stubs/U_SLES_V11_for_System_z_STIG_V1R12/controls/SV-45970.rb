control 'SV-45970' do
  title 'The Datagram Congestion Control Protocol (DCCP) must be disabled unless required.'
  desc 'The DCCP is a proposed transport layer protocol.  This protocol is not yet widely used.  Binding this protocol to the network stack increases the attack surface of the host.  Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', "Verify the DCCP protocol handler is prevented from dynamic loading.
# grep 'install dccp' /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/* | grep ‘/bin/true’
If no result is returned, this is a finding.
# grep 'install dccp_ipv4' /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/* | grep /bin/true’

If no result is returned, this is a finding.
# grep 'install dccp_ipv6' /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/* | grep ‘bin/true’
If no result is returned, this is a finding."
  desc 'fix', 'Prevent the DCCP protocol handler for dynamic loading.
# echo "install dccp /bin/true" >> /etc/modprobe.conf.local
# echo "install dccp_ipv4 /bin/true" >> /etc/modprobe.conf.local
# echo "install dccp_ipv6 /bin/true" >> /etc/modprobe.conf.local'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43252r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22514'
  tag rid: 'SV-45970r1_rule'
  tag stig_id: 'GEN007080'
  tag gtitle: 'GEN007080'
  tag fix_id: 'F-39335r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
