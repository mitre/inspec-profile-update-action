control 'SV-218677' do
  title 'The Datagram Congestion Control Protocol (DCCP) must be disabled unless required.'
  desc 'The DCCP is a proposed transport layer protocol.  This protocol is not yet widely used.  Binding this protocol to the network stack increases the attack surface of the host.  Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', "Verify the DCCP protocol handler is prevented from dynamic loading.
# grep 'install dccp /bin/true' /etc/modprobe.conf /etc/modprobe.d/*
If no result is returned, this is a finding.
# grep 'install dccp_ipv4 /bin/true' /etc/modprobe.conf /etc/modprobe.d/*
If no result is returned, this is a finding.
# grep 'install dccp_ipv6 /bin/true' /etc/modprobe.conf /etc/modprobe.d/*
If no result is returned, this is a finding."
  desc 'fix', 'Prevent the DCCP protocol handler for dynamic loading.
# echo "install dccp /bin/true" >> /etc/modprobe.conf
# echo "install dccp_ipv4 /bin/true" >> /etc/modprobe.conf
# echo "install dccp_ipv6 /bin/true" >> /etc/modprobe.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20152r556445_chk'
  tag severity: 'medium'
  tag gid: 'V-218677'
  tag rid: 'SV-218677r603259_rule'
  tag stig_id: 'GEN007080'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-20150r556446_fix'
  tag 'documentable'
  tag legacy: ['V-22514', 'SV-63521']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
