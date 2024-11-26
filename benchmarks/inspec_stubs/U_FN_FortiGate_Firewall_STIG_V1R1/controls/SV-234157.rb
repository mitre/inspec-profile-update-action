control 'SV-234157' do
  title 'The FortiGate firewall must be configured to restrict it from accepting outbound packets that contain an illegitimate address in the source address field via an egress filter or by enabling Unicast Reverse Path Forwarding (uRPF).'
  desc 'A compromised host in an enclave can be used by a malicious platform to launch cyberattacks on third parties. This is a common practice in "botnets", which are a collection of compromised computers using malware to attack other computers or networks. Denial-of-Service (DoS) attacks frequently leverage IP source address spoofing to send packets to multiple hosts that, in turn, send return traffic to the hosts with the forged IP addresses. This can generate significant amounts of traffic. Therefore, protection measures to counteract IP source address spoofing must be taken. When uRPF is enabled in strict mode, the packet must be received on the interface that the device would use to forward the return packet, thereby mitigating IP source address spoofing.'
  desc 'check', 'The FortiGate has RPF enabled by default, but it can be disabled for IPv4, IPv4 ICMP, IPv6, and IPv6-ICMP with the "set asymroute enable" commands. Log in to the FortiGate CLI with Super-Admin privilege, and then run the command:
# get system settings | grep asymroute

Unless this device is intentionally setup for asymmetric routing, if any of the settings are set to "enable" this is a finding.'
  desc 'fix', 'This fix can be performed via the CLI of the FortiGate.

1. Open a CLI console via SSH or from the GUI.
2. Run the following commands:
     # config system settings
     #    set asymroute disable
     #    set asymroute-icmp disable
     #    set asymroute6 disable
     #    set asymroute6-icmp disable
     # end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37342r611469_chk'
  tag severity: 'medium'
  tag gid: 'V-234157'
  tag rid: 'SV-234157r628776_rule'
  tag stig_id: 'FNFG-FW-000145'
  tag gtitle: 'SRG-NET-000364-FW-000042'
  tag fix_id: 'F-37307r611470_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
