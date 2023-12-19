control 'SV-240448' do
  title 'The Lightweight User Datagram Protocol (UDP-Lite) must be disabled unless required.'
  desc 'The Lightweight User Datagram Protocol (UDP-Lite) is a proposed transport layer protocol. This protocol is not yet widely used. Binding this protocol to the network stack increases the attack surface of the host. Unprivileged local processes may be able to cause the system to dynamically load a protocol handler by opening a socket using the protocol.'
  desc 'check', 'Run the following command:

iptables --list | grep "udplite"

If no result is displayed, this is a finding.'
  desc 'fix', 'Configure the system to prevent the dynamic loading of the UDP-Lite protocol handler:

Add the following rule to the iptables firewall ruleset:

# iptables -A INPUT -p udplite -j DROP'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43681r671083_chk'
  tag severity: 'medium'
  tag gid: 'V-240448'
  tag rid: 'SV-240448r671085_rule'
  tag stig_id: 'VRAU-SL-000635'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-43640r671084_fix'
  tag 'documentable'
  tag legacy: ['SV-100323', 'V-89673']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
