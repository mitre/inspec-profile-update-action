control 'SV-256014' do
  title 'The PE router must be configured to enforce a Quality-of-Service (QoS) policy in accordance with the QoS GIG Technical Profile.'
  desc 'Different applications have unique requirements and toleration levels for delay, jitter, bandwidth, packet loss, and availability. To manage the multitude of applications and services, a network requires a QoS framework to differentiate traffic and provide a method to manage network congestion. The Differentiated Services Model (DiffServ) is based on per-hop behavior by categorizing traffic into different classes and enabling each node to enforce a forwarding treatment to each packet as dictated by a policy.

Packet markings such as IP Precedence and its successor, Differentiated Services Code Points (DSCP), were defined along with specific per-hop behaviors for key traffic types to enable a scalable QoS solution. DiffServ QoS categorizes network traffic, prioritizes it according to its relative importance, and provides priority treatment based on the classification. It is imperative that end-to-end QoS is implemented within the IP core network to provide preferred treatment for mission-critical applications.'
  desc 'check', 'Review the router configuration and verify that a QoS policy has been configured to provide preferred treatment for mission-critical applications in accordance with the QoS GIG Technical Profile. 

Step 1: Verify the Arista router class-maps are configured to match on DSCP, protocols, or access control lists (ACLs) that identify traffic types based on ports.

router#sh qos map
qos map dscp 0 1 2 3 4 5 6 7 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 40 41 42 43 44 46 47 48 50 51 52 53 54 55 56 57 58 59 60 61 62 63 to traffic-class 0
qos map dscp 11 to traffic-class 1
qos map dscp 39 to traffic-class 2
qos map dscp 15 49 to traffic-class 3
!

Step 2: Verify the Arista router policy-map is configured to set DSCP values for the defined class-maps in accordance with the QoS GIG Technical Profile.

router#sh run |sec port-channel33
interface Port-Channel33
   description L3-Routed-PO33->Distro1-QFX5200-32C-100G
   routerport trunk allowed vlan 2100-2102,4033
   routerport mode trunk
   routerport trunk group 4033
   qos trust dscp
   !
   tx-queue 0
      bandwidth percent 20
   !
   tx-queue 1
      bandwidth percent 40
      shape rate 40088888
   !
   tx-queue 2
      bandwidth percent 15
      shape rate 15022222
   !
   tx-queue 3
      bandwidth percent 25
      shape rate 25250000

Step 3: Verify that an output service policy is bound to all interfaces.

router#sh run | section qos
interface Vlan33
   service-policy type qos input policy3
hardware tcam
   profile QOS_TEST
      feature acl port ip
         sequence 45
         key size limit 160
         key field dscp dst-ip ip-frag ip-protocol l4-dst-port l4-ops l4-src-port src-ip tcp-control ttl
         action count drop mirror
         packet ipv4 forwarding bridged
         packet ipv4 forwarding routed
         packet ipv4 forwarding routed multicast
         packet ipv4 mpls ipv4 forwarding mpls decap
         packet ipv4 mpls ipv6 forwarding mpls decap
         packet ipv4 non-vxlan forwarding routed decap
         packet ipv4 vxlan eth ipv4 forwarding routed decap
         packet ipv4 vxlan forwarding bridged decap
      !
feature acl port ip egress mpls-tunnelled-match
         sequence 100
      !
      feature acl port ipv6
         sequence 25
         key field dst-ipv6 ipv6-next-header ipv6-traffic-class l4-dst-port l4-ops-3b l4-src-port src-ipv6-high src-ipv6-low tcp-control
         action count drop mirror
         packet ipv6 forwarding bridged
         packet ipv6 forwarding routed
         packet ipv6 forwarding routed multicast
         packet ipv6 ipv6 forwarding routed decap
      !
      feature acl port ipv6 egress
         sequence 110
         key field dst-ipv6 ipv6-next-header ipv6-traffic-class l4-dst-port l4-src-port src-ipv6-high src-ipv6-low tcp-control
         action count drop
         packet ipv6 forwarding bridged
         packet ipv6 forwarding routed
      !
      feature acl port mac
         sequence 55
         key size limit 160
         key field dst-mac ether-type src-mac
         action count drop mirror
         packet ipv4 forwarding bridged
         packet ipv4 forwarding routed
         packet ipv4 forwarding routed multicast
         packet ipv4 mpls ipv4 forwarding mpls decap
         packet ipv4 mpls ipv6 forwarding mpls decap
         packet ipv4 non-vxlan forwarding routed decap
         packet ipv4 vxlan forwarding bridged decap
         packet ipv6 forwarding bridged
         packet ipv6 forwarding routed
         packet ipv6 forwarding routed decap
         packet ipv6 forwarding routed multicast
         packet ipv6 ipv6 forwarding routed decap
         packet mpls forwarding bridged decap
         packet mpls ipv4 forwarding mpls
         packet mpls ipv6 forwarding mpls
         packet mpls non-ip forwarding mpls
         packet non-ip forwarding bridged
      !

Step 4: Verify the Arista router is configured for a minimum four queues, 0 through 3, for (Port-Channel33) as round robin, with voice strict-priority. The allocated bandwidth for queue (0) 19.6%, queue (1) 39.6%, queue (2) 14.9%, and queue (3) 24.9%. The bandwidth percentages allow for control-plane and protocol management traffic. These configurations allow burst traffic levels and shape rates for maximum outbound traffic bandwidth per queue.

router#sh qos int po33
Port-Channel33:
   Trust Mode: DSCP
   Default COS: 0
   Default DSCP: 0
   Port shaping rate: enabled
  Tx    Bandwidth     Bandwidth                   Shape Rate         Priority   ECN/WRED 
 Queue  (percent)     Guaranteed (units)           (units)         
 ----------------------------------------------------------------------------------------
   7        -             - ( - )              -            ( - )      SP         D     
   6        -             - ( - )              -            ( - )      SP         D     
   5        -             - ( - )              -            ( - )      SP         D     
   4        -             - ( - )              -            ( - )      SP         D     
   3        25          - ( - )           24.9      (Gbps)   SP        D     
   2        15          - ( - )           14.8      (Gbps)   RR       D     
   1        40          - ( - )           39.6      (Gbps)   RR       D     
   0        20          - ( - )              -            ( - )       RR       D

Legend:
RR -> Round Robin
SP -> Strict Priority
 - -> Not Applicable / Not Configured
 % -> Percentage of reference
ECN/WRED: L -> Queue Length ECN Enabled     W -> WRED Enabled     D -> Disabled

Note: The GTP QOS document (GTP-0009) can be downloaded via the following link:
https://intellipedia.intelink.gov/wiki/Portal:GIG_Technical_Guidance/GTG_GTPs/GTP_Development_List

If the Arista router is not configured to implement a QoS policy in accordance with the QoS GIG Technical Profile, this is a finding.'
  desc 'fix', 'Configure a QoS policy on each router in accordance with the QoS GIG Technical Profile.

Step 1: Configure the Arista router class-maps to match on DSCP Quality of Service Differentiated Service Code Points (DSCP) values to identify four traffic-class into Class 0 (0-7, 16-38, 40-44, 46-48, 50-63) Class 1 (11) Class 2 (39) Class 3 (15, 49).

router(config)#qos map
qos map dscp 0 1 2 3 4 5 6 7 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 40 41 42 43 44 46 47 48 50 51 52 53 54 55 56 57 58 59 60 61 62 63 to traffic-class 0
qos map dscp 11 to traffic-class 1
qos map dscp 39 to traffic-class 2
qos map dscp 15 49 to traffic-class 3
!

Step 2: Configure the Arista router bandwidth and shape rates based on four queues defined by DSCP and the defined class-maps in accordance with the QoS GIG Technical Profile.

router(config)#interface Port-Channel33
router(config-if-po33)#description PO33->Distro1-QFX5200-32C-100G
   routerport trunk allowed vlan 2100-2102,4033
   routerport mode trunk
   routerport trunk group 4033
   qos trust dscp
   !
   tx-queue 0
      bandwidth percent 20
   !
   tx-queue 1
      bandwidth percent 40
      shape rate 40088888
   !
   tx-queue 2
      bandwidth percent 15
      shape rate 15022222
   !
   tx-queue 3
      bandwidth percent 25
      shape rate 25250000
!

Step 3: Configure the Arista router for queues 0 through 3 for Interface (Port-Channel33) as round robin, with voice strict-priority, and then allocate bandwidth for four queues. queue (0) 19.6%, queue (1) 39.6%, queue (2) 14.9%, and queue (3) 24.9%. allowing for control-plane and protocol management traffic. These configurations allow burst traffic levels and shape rates for maximum outbound traffic bandwidth per queue.

router#sh qos int po33
Port-Channel33:
   Trust Mode: DSCP
   Default COS: 0
   Default DSCP: 0
   Port shaping rate: enabled
  Tx    Bandwidth     Bandwidth                   Shape Rate         Priority   ECN/WRED 
 Queue  (percent)     Guaranteed (units)           (units)         
 ----------------------------------------------------------------------------------------
   7        -             - ( - )              -            ( - )      SP         D     
   6        -             - ( - )              -            ( - )      SP         D     
   5        -             - ( - )              -            ( - )      SP         D     
   4        -             - ( - )              -            ( - )      SP         D     
   3        25          - ( - )           24.9      (Gbps)   SP        D     
   2        15          - ( - )           14.9      (Gbps)   RR       D     
   1        40          - ( - )           39.6      (Gbps)   RR       D     
   0        20          - ( - )              -            ( - )       RR       D

Legend:
RR -> Round Robin
SP -> Strict Priority
 - -> Not Applicable / Not Configured
 % -> Percentage of reference
ECN/WRED: L -> Queue Length ECN Enabled     W -> WRED Enabled     D -> Disabled'
  impact 0.3
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59690r882382_chk'
  tag severity: 'low'
  tag gid: 'V-256014'
  tag rid: 'SV-256014r882384_rule'
  tag stig_id: 'ARST-RT-000320'
  tag gtitle: 'SRG-NET-000193-RTR-000114'
  tag fix_id: 'F-59633r882383_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
