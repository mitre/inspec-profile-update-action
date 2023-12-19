control 'SV-221135' do
  title 'The Cisco multicast Rendezvous Point (RP) switch must be configured to limit the multicast forwarding cache so that its resources are not saturated by managing an overwhelming number of Protocol Independent Multicast (PIM) and Multicast Source Discovery Protocol (MSDP) source-active entries.'
  desc 'MSDP peering between networks enables sharing of multicast source information. Enclaves with an existing multicast topology using PIM-SM can configure their RP switches to peer with MSDP switches. As a first step of defense against a denial-of-service (DoS) attack, all RP switches must limit the multicast forwarding cache to ensure that switch resources are not saturated managing an overwhelming number of PIM and MSDP source-active entries.'
  desc 'check', 'The Cisco switch does not have a mechanism to limit the multicast forwarding cache. However, the risk associated with this requirement can be fully mitigated by configuring the switch to filter PIM register messages and accept MSDP packets only from known MSDP peers. 

Step 1: Verify that the RP is configured to filter PIM register messages for any undesirable multicast groups and sources. The example below will deny any multicast streams for groups 239.5.0.0/16 and allow from only sources x.1.2.6 and x.1.2.7. 

ip pim register-policy PIM_REGISTER_FILTER
…
…
…
route-map PIM_REGISTER_FILTER deny 10
 match ip multicast group 239.5.0.0/16 
route-map PIM_REGISTER_FILTER permit 20
 match ip multicast source x.1.2.6/32 
route-map PIM_REGISTER_FILTER permit 30
 match ip multicast source x.1.2.7/32 
route-map PIM_REGISTER_FILTER permit 40
 match ip multicast group-range 232.0.0.0 to 233.255.255.255 
route-map PIM_REGISTER_FILTER deny 50
 match ip multicast source 0.0.0.0/0

Step 2: Review the switch configuration to determine if there is a receive path or interface filter to only accept MSDP packets from known MSDP peers as shown in the example below. 

Step 2a: Verify that interfaces used for MSDP peering have an inbound ACL as shown in the example.

interface Ethernet2/3
 no switchport
 ip access-group EXTERNAL_ACL_INBOUND in
 ip address x.1.28.8/24
 ip pim sparse-mode

Step 2b: Verify that the ACL restricts MSDP peering to only known sources.

ip access-list EXTERNAL_ACL_INBOUND
 10 permit tcp any any established 
 20 permit tcp x.1.28.2/32 x.1.28.8/32 eq 639 
 30 deny tcp any x.1.28.8/32 eq 639 log 
 40 permit tcp x.1.28.2/32 10.x.28.8/32 eq bgp 
 50 permit tcp x.1.28.2/32 eq bgp x.1.28.8/32 
 60 permit pim x.1.28.2/32 x.1.28.8/32 
…
 …
 …
120 deny ip any any log

Note: MSDP connections is via TCP port 639.

If the RP switch is not configured to filter PIM register messages and accept MSDP packets only from known MSDP peers, this is a finding.'
  desc 'fix', 'The risk associated with this requirement can be fully mitigated by configuring the switch to filter PIM register messages, rate limiting the number of PIM register messages, and accept MSDP packets only from known MSDP peers. 

Step 1: Configure the switch to filter PIM register messages received from a multicast DR for any undesirable multicast groups and sources. The example below will deny any multicast streams for groups 239.5.0.0/16 and allow from only sources x.1.2.6 and x.1.2.7. 

Step 1a: Configure a route map to filter multicast groups and sources as shown in the example below:

SW1(config)# route-map PIM_REGISTER_FILTER deny 10 
SW1(config-route-map)# match ip multicast group 239.5.0.0/16 
SW1(config-route-map)# route-map PIM_REGISTER_FILTER permit 20
SW1(config-route-map)# match ip multicast source x.1.2.6/32
SW1(config-route-map)# route-map PIM_REGISTER_FILTER permit 30
SW1(config-route-map)# match ip multicast source x.1.2.7/32
SW1(config-route-map)# route-map PIM_REGISTER_FILTER permit 40
SW1(config-route-map)# match ip multicast group-range 232.0.0.0 to 233.255.255.255
SW1(config-route-map)# route-map PIM_REGISTER_FILTER deny 50
SW1(config-route-map)# match ip multicast source 0.0.0.0/0
SW1(config-route-map)# exit

Step 1b: Configure a multicast register policy referencing the configured route map.

SW1(config)# ip pim register-policy PIM_REGISTER_FILTER
SW1(config)# end

Step 2: Configure the receive path or interface ACLs to only accept MSDP packets from known MSDP peers. 

SW1(config)# ip access-list EXTERNAL_ACL_INBOUND
SW1(config-acl) # permit tcp any any established
SW1(config-acl) # permit tcp host x.1.28.2 host x.1.28.8 eq 639
SW1(config-acl) # deny tcp any host x1.28.8 eq 639
SW1(config-acl) # permit tcp host x.1.28.2 host x.1.28.8 eq bgp
SW1(config-acl) # permit tcp host x.1.28.2 eq bgp host x.1.28.8
SW1(config-acl) # permit pim host x.1.28.2 host x.1.28.8
…
…
…
SW1(config-acl)# deny ip any any'
  impact 0.3
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22850r409894_chk'
  tag severity: 'low'
  tag gid: 'V-221135'
  tag rid: 'SV-221135r622190_rule'
  tag stig_id: 'CISC-RT-000820'
  tag gtitle: 'SRG-NET-000362-RTR-000120'
  tag fix_id: 'F-22839r409895_fix'
  tag 'documentable'
  tag legacy: ['SV-111089', 'V-101985']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
