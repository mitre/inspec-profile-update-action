control 'SV-256012' do
  title 'The PE router must be configured to enforce a Quality-of-Service (QoS) policy to limit the effects of packet flooding denial-of-service (DoS) attacks.'
  desc 'DoS is a condition when a resource is not available for legitimate users. Packet flooding distributed denial-of-service (DDoS) attacks are referred to as volumetric attacks and have the objective of overloading a network or circuit to deny or seriously degrade performance, which denies access to the services that normally traverse the network or circuit. Volumetric attacks have become relatively easy to launch using readily available tools such as Low Orbit Ion Cannon or botnets. 

Measures to mitigate the effects of a successful volumetric attack must be taken to ensure that sufficient capacity is available for mission-critical traffic. Managing capacity may include, for example, establishing selected network usage priorities or quotas and enforcing them using rate limiting, Quality of Service (QoS), or other resource reservation control methods. These measures may also mitigate the effects of sudden decreases in network capacity that are the result of accidental or intentional physical damage to telecommunications facilities (such as cable cuts or weather-related outages).'
  desc 'check', 'Review the Arista router configuration and interview the System Administrator to verify that a mechanism for traffic prioritization and bandwidth reservation exists.

This arrangement must ensure that sufficient capacity is available for mission-critical traffic and enforce the traffic priorities specified by the Combatant Commands/Services/Agencies.

Review the Arista router configuration to verify traffic prioritization and bandwidth reservations.

router#sh run | sec bandwidth
interface Port-Channel33
   tx-queue 0
      bandwidth percent 20
   tx-queue 1
      bandwidth percent 40
   tx-queue 2
      bandwidth percent 15
   tx-queue 3
      bandwidth percent 25
policy-map type copp copp-system-policy
   class copp-system-lldp
      bandwidth kbps 500

If no such scheme exists or it is not configured, this is a finding.'
  desc 'fix', 'Implement a mechanism for traffic prioritization and bandwidth reservation. This mechanism must enforce the traffic priorities specified by the Combatant Commands/Services/Agencies.

Step 1: Configure the Arista router for traffic queuing based on traffic prioritization and bandwidth reservation.

router(config)#vlan 4033
   trunk group 4033
!
interface Port-Channel33
   description L3-PO33->Distro1-QFX5200-32C-100G
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

Step 2: Configure the Arista router differentiated services code point (DSCP) with a 6-bit field in the IP header, which marks all traffic for protocol-specific traffic with the configured DSCP value.

router(config)#qos map dscp 0 1 2 3 4 5 6 7 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 40 41 42 43 44 46 47 48 50 51 52 53 54 55 56 57 58 59 60 61 62 63 to traffic-class 0
qos map dscp 11 to traffic-class 1
qos map dscp 39 to traffic-class 2
qos map dscp 15 49 to traffic-class 3
!

Step 3: Configure the Arista router trusted routed links with the quality of service port trust mode on the Ethernet interface. 

router(config)#interface Ethernet 2
description OSPF LINK TO DODIN ENCLAVE
   no routerport
   ip address 172.16.50.1/30
   ipv6 nd ra hop-limit 32
   ip access-group STIG in
   ip ospf authentication message-digest
   ip ospf message-digest-key 1 md5 7 OQ62NhxhqcbWEps4eZjZOg==
   ipv6 ospf encryption ipsec spi 1 esp null sha1 passphrase 7 ZauLr6BwU+Q1MGMLbbys9A==
   qos trust dscp'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59688r882376_chk'
  tag severity: 'medium'
  tag gid: 'V-256012'
  tag rid: 'SV-256012r882378_rule'
  tag stig_id: 'ARST-RT-000300'
  tag gtitle: 'SRG-NET-000193-RTR-000112'
  tag fix_id: 'F-59631r882377_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
