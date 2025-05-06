control 'SV-256032' do
  title 'The Arista router must be configured to have Internet Control Message Protocol (ICMP) unreachable notifications disabled on all external interfaces.'
  desc 'The ICMP supports IP traffic by relaying information about paths, routes, and network conditions. Routers automatically send ICMP messages under a wide variety of conditions. Host unreachable ICMP messages are commonly used by attackers for network mapping and diagnosis.'
  desc 'check', 'Review the device configuration to determine if controls have been defined to ensure the router does not send ICMP unreachable notifications out to any external interfaces.

Step 1: To verify the ACL is configured to determine the router does not send ICMP unreachable notifications out to any external interfaces, execute the command "sh ip access-list".

ip access-group DENY_ICMP_UNREACHABLE
 deny icmp any any unreachable
 permit ip any any

Step 2: To verify the ACL is applied outbound on interfaces, execute the command "sh run int Eth YY".

interface Ethernet 2
 ip access-group DENY_ICMP_UNREACHABLE out

If ICMP unreachable notifications are enabled on any external interfaces, this is a finding.'
  desc 'fix', 'Disable ICMP unreachable notifications on all external interfaces.

Step 1: The Arista router can be configured to filter out the ICMP Unreachable for (Type 3) code 0 (Network unreachable) IPv4 and IPv6 packets with the following command:

router(config)#ip icmp rate-limit-unreachable 0
router(config)#ipv6 icmp rate-limit-unreachable 0

Step 2: The Arista router can be configured to filter out the ICMP Unreachable for (Type 3) code 1 (Network unreachable) IPv4 and IPv6 packets with the following command:

router(config)#ip access-list BLK-ICMP-Unreachables
10 deny icmp any any host-unreachable
20 permit ip any any
!

Step 3: This would need to be applied on the egress interface (for example as in et1 below):

router(config)#interface ethernet1
no routerport
ip address 32.1.1.12/24
ip access-group BLK-ICMP-Unreachables out
!'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59708r882436_chk'
  tag severity: 'medium'
  tag gid: 'V-256032'
  tag rid: 'SV-256032r882438_rule'
  tag stig_id: 'ARST-RT-000530'
  tag gtitle: 'SRG-NET-000362-RTR-000113'
  tag fix_id: 'F-59651r882437_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
