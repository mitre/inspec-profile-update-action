control 'SV-256016' do
  title 'The Arista router must be configured to restrict traffic destined to itself.'
  desc 'The route processor handles traffic destined to the router, the key component used to build forwarding paths that is also instrumental with all network management functions. Hence, any disruption or denial-of-service (DoS) attack to the route processor can result in mission-critical network outages.'
  desc 'check', 'Review the access control list (ACL) or filter for the Arista router receive path and verify that it will only process specific management plane and control plane traffic from specific sources.

Note: If the platform does not support the receive path filter, verify all layer 3 interfaces have an ingress ACL to control what packets are allowed to be destined to the router for processing.

Step 1: Review the Arista router configuration for Control Plane ACL, which can be modified to permit or deny additional protocols that can be matched via an extended access-list for management traffic. Sample Default CP ACL:

!
ip access-list ENCLAVE_GATEWAY_FILTER
   10 permit ip any 172.16.0.0/16
!
ip access-list STIG
   10 deny ip 172.16.50.0/30 10.10.100.0/24
!
ip access-list control-plane-modified
   !! Line 180 added for AMLS-L3-000260 which requires eBGP GTSM or equivalent
   statistics per-entry
   10 permit icmp any any
   20 permit ip any any tracked
   30 permit udp any any eq bfd ttl eq 255
   40 permit udp any any eq bfd-echo ttl eq 254
   50 permit ospf any any
   60 permit tcp any any eq ssh telnet www snmp bgp https msdp
   70 permit udp any any eq bootps bootpc snmp rip ntp
   80 permit tcp any any eq mlag ttl eq 255
   90 permit udp any any eq mlag ttl eq 255
   100 permit vrrp any any
   110 permit ahp any any
   120 permit pim any any
   130 permit igmp any any
   140 permit tcp any any range 5900 5910
   150 permit tcp any any range 50000 50100
   160 permit udp any any range 51000 51100
   170 permit tcp any any eq mlag-arp-sync ttl eq 255
   180 permit tcp 192.168.1.0/30 192.168.1.0/30 eq bgp ttl eq 255 log 

Step 2: Verify the control plane policy is configured to restricting the LLDP traffic to CPU.

router#show running-config | section policy-map
policy-map type copp copp-system-policy
   class copp-system-lldp
   bandwidth kbps 500

Step 3: To verify the ACL is configured to allow the traffic per the requirement and deny all by default, execute the command "sh ip access-list".

router#show ip access-list
ip access-list INBOUND
   10 permit tcp 10.10.10.0/24 host 10.20.10.1 eq ssh telnet
   20 permit tcp 10.10.10.0/24 any eq www https
   30 permit udp 10.20.20.0/24 any eq bootps snmp

Step 4: To verify the ACL is applied inbound on all external interfaces, execute the command "sh run int Eth YY".

router#show running-config interface Ethernet 13
interface ethernet 13
  ip access-group INBOUND in

If the Arista router is not configured with a receive-path filter to restrict traffic destined to itself, this is a finding.'
  desc 'fix', 'Configure all Arista routers with receive path filters to restrict traffic destined to the router.

Step 1: Configure the Control plane policy to restrict the LLDP traffic to CPU.

router(config)#policy-map type copp copp-system-policy
router(config-pmap-copp-system-policy)#class copp-system-lldp
router(config-pmap-c-copp-system-policy-copp-system-lldp)#bandwidth kbps 500

Step 2: Configure an ACL inbound to allow traffic per the requirement and deny all by default.

ip access-list INBOUND
   10 permit tcp 10.10.10.0/24 host 10.20.10.1 eq ssh telnet
   20 permit tcp 10.10.10.0/24 any eq www https
   30 permit udp 10.20.20.0/24 any eq bootps snmp

Step 3: Apply the ACL inbound on all external interfaces.

router(config)#interface ethernet 13
router(config-if-Et13)#ip access-group INBOUND in'
  impact 0.7
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59692r882388_chk'
  tag severity: 'high'
  tag gid: 'V-256016'
  tag rid: 'SV-256016r882390_rule'
  tag stig_id: 'ARST-RT-000340'
  tag gtitle: 'SRG-NET-000205-RTR-000001'
  tag fix_id: 'F-59635r882389_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
