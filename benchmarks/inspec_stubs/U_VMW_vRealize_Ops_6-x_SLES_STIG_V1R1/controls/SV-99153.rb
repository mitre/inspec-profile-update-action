control 'SV-99153' do
  title 'The Datagram Congestion Control Protocol (DCCP) must be disabled unless required.'
  desc 'The Datagram Congestion Control Protocol (DCCP) is a proposed transport layer protocol. This protocol is not yet widely used. Binding this protocol to the network stack increases the attack surface of the host. Unprivileged local processes may be able to cause the kernel to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'Check that the DCCP protocol handler is prevented from dynamic loading:

# grep "install dccp /bin/true" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/* 

If no result is returned, this is a finding.

# grep "install dccp_ipv4 /bin/true" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/* 

If no result is returned, this is a finding.

# grep "install dccp_ipv6" /etc/modprobe.conf /etc/modprobe.conf.local /etc/modprobe.d/* | grep ‘bin/true’

If no result is returned, this is a finding.'
  desc 'fix', 'Prevent the DCCP protocol handler for dynamic loading:

# echo "install dccp /bin/true" >> /etc/modprobe.conf.local
# echo "install dccp_ipv4 /bin/true" >> /etc/modprobe.conf.local
# echo "install dccp_ipv6 /bin/true" >> /etc/modprobe.conf.local'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88195r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88503'
  tag rid: 'SV-99153r1_rule'
  tag stig_id: 'VROM-SL-000485'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-95245r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
