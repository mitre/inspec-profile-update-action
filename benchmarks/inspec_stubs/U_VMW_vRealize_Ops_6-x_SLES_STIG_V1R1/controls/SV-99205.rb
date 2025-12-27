control 'SV-99205' do
  title 'The Lightweight User Datagram Protocol (UDP-Lite) must be disabled unless required.'
  desc 'The Lightweight User Datagram Protocol (UDP-Lite) is a proposed transport layer protocol. This protocol is not yet widely used. Binding this protocol to the network stack increases the attack surface of the host. Unprivileged local processes may be able to cause SLES for vRealize  to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'Run the following command:

iptables --list | grep "udplite"

If no result is displayed, this is a finding.'
  desc 'fix', 'Configure SLES for vRealize to prevent the dynamic loading of the "UDP-Lite" protocol handler:

Add the following rule to the iptables firewall ruleset:

# iptables -A INPUT -p udplite -j DROP'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88247r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88555'
  tag rid: 'SV-99205r1_rule'
  tag stig_id: 'VROM-SL-000615'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-95297r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
