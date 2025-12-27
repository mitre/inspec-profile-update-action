control 'SV-239516' do
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
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42749r661997_chk'
  tag severity: 'medium'
  tag gid: 'V-239516'
  tag rid: 'SV-239516r661999_rule'
  tag stig_id: 'VROM-SL-000485'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-42708r661998_fix'
  tag 'documentable'
  tag legacy: ['SV-99153', 'V-88503']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
