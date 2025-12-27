control 'SV-216809' do
  title 'The Cisco multicast edge router must be configured to establish boundaries for administratively scoped multicast traffic.'
  desc 'If multicast traffic is forwarded beyond the intended boundary, it is possible that it can be intercepted by unauthorized or unintended personnel.

Administrative scoped multicast addresses are locally assigned and are to be used exclusively by the enterprise network or enclave. Administrative scoped multicast traffic must not cross the enclave perimeter in either direction. Restricting multicast traffic makes it more difficult for a malicious user to access sensitive traffic.

Admin-Local scope is encouraged for any multicast traffic within a network intended for network management, as well as for control plane traffic that must reach beyond link-local destinations.'
  desc 'check', 'Review the router configuration and verify that admin-scope multicast traffic is blocked at the external edge as shown in the example below.

ipv4 access-list MULTICAST_SCOPE
 10 deny ipv4 239.0.0.0 0.255.255.255 any
 20 permit ipv4 any any
…
…
…

multicast-routing
 address-family ipv4
  interface GigabitEthernet0/0/0/1
   enable
   boundary MULTICAST_SCOPE
  !
  interface GigabitEthernet0/0/0/2
   enable
  !
 !
!

If the router is not configured to establish boundaries for administratively scoped multicast traffic, this is a finding.'
  desc 'fix', 'Step 1: Configure the ACL to deny packets with multicast administratively scoped destination addresses as shown in the example below.

RP/0/0/CPU0:R2(config)#Ipv4 access-list MULTICAST_SCOPE
RP/0/0/CPU0:R2(config-ipv4-acl)#deny 239.0.0.0 0.255.255.255
RP/0/0/CPU0:R2(config-ipv4-acl)#permit any

Step 2: Apply the multicast boundary at the appropriate interfaces as shown in the example below.

RP/0/0/CPU0:R2(config)#multicast-routing 
RP/0/0/CPU0:R2(config-mcast)#address-family ipv4
RP/0/0/CPU0:R2(config-mcast-default-ipv4)#int g0/0/0/1
RP/0/0/CPU0:R2(config-mcast-default-ipv4-if)#boundary MULTICAST_SCOPE
RP/0/0/CPU0:R2(config-mcast-default-ipv4-if)#end'
  impact 0.3
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18041r288801_chk'
  tag severity: 'low'
  tag gid: 'V-216809'
  tag rid: 'SV-216809r531087_rule'
  tag stig_id: 'CISC-RT-000810'
  tag gtitle: 'SRG-NET-000019-RTR-000005'
  tag fix_id: 'F-18039r288802_fix'
  tag 'documentable'
  tag legacy: ['SV-105963', 'V-96825']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
