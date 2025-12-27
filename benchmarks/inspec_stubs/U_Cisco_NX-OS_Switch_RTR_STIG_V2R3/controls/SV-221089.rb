control 'SV-221089' do
  title 'The Cisco perimeter switch must be configured to only allow incoming communications from authorized sources to be routed to authorized destinations.'
  desc "Unrestricted traffic may contain malicious traffic that poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

Traffic can be restricted directly by an access control list (ACL), which is a firewall function, or by Policy Routing. Policy Routing is a technique used to make routing decisions based on a number of different criteria other than just the destination network, including source or destination network, source or destination address, source or destination port, protocol, packet size, and packet classification. This overrides the switch's normal routing procedures used to control the specific paths of network traffic. It is normally used for traffic engineering but can also be used to meet security requirements; for example, traffic that is not allowed can be routed to the Null0 or discard interface. Policy Routing can also be used to control which prefixes appear in the routing table.

This requirement is intended to allow network administrators the flexibility to use whatever technique is most effective."
  desc 'check', 'Review the switch configuration to determine if the switch allows only incoming communications from authorized sources to be routed to authorized destinations. The hypothetical example below allows inbound NTP from server x.1.12.9 only to host x.12.1.21.

ip access-list EXTERNAL_ACL
 10 permit tcp any any established 
 20 permit tcp x.11.1.1/32 eq bgp x.11.1.2/32 
 30 permit tcp x.11.1.1/32 x.11.1.2/32 eq bgp 
 40 permit icmp x.11.1.1/32 x.11.1.2/32 echo 
 50 permit icmp x.11.1.1/32 x.11.1.2/32 echo-reply 
 60 permit tcp any x.11.2.3/32 eq www 
 70 permit udp x.12.1.9/32 x.12.1.21/32 eq ntp 
…
 …
 …
90 deny ip any any log

If the switch does not restrict incoming communications to allow only authorized sources and destinations, this is a finding.'
  desc 'fix', 'Configure the switch to allow only incoming communications from authorized sources to be routed to authorized destinations. 

SW2(config)# ip access-list EXTERNAL_ACL
SW2(config-acl)# permit tcp any any established
…
…
…
SW2(config-acl)# permit udp host x.12.1.9 host x.12.1.21 eq ntp
SW2(config-acl)# deny ip any any log
SW2(config-acl)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22804r409756_chk'
  tag severity: 'medium'
  tag gid: 'V-221089'
  tag rid: 'SV-221089r856646_rule'
  tag stig_id: 'CISC-RT-000260'
  tag gtitle: 'SRG-NET-000364-RTR-000109'
  tag fix_id: 'F-22793r409757_fix'
  tag 'documentable'
  tag legacy: ['SV-110997', 'V-101893']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
