control 'SV-216624' do
  title 'The Cisco multicast edge router must be configured to establish boundaries for administratively scoped multicast traffic.'
  desc 'If multicast traffic is forwarded beyond the intended boundary, it is possible that it can be intercepted by unauthorized or unintended personnel.

Administrative scoped multicast addresses are locally assigned and are to be used exclusively by the enterprise network or enclave. Administrative scoped multicast traffic must not cross the enclave perimeter in either direction. Restricting multicast traffic makes it more difficult for a malicious user to access sensitive traffic.

Admin-Local scope is encouraged for any multicast traffic within a network intended for network management, as well as for control plane traffic that must reach beyond link-local destinations.'
  desc 'check', 'Review the router configuration and verify that admin-scope multicast traffic is blocked at the external edge as shown in the example below.

interface GigabitEthernet1/2
 ip address x.1.12.2 255.255.255.252
 ip pim sparse-mode
 ip multicast boundary MULTICAST_SCOPE
…
…
…
ip access-list standard MULTICAST_SCOPE
 deny   239.0.0.0 0.255.255.255
 permit any

If the router is not configured to establish boundaries for administratively scoped multicast traffic, this is a finding.'
  desc 'fix', 'Step 1: Configure the ACL to deny packets with multicast administratively scoped destination addresses as shown in the example below.

R2(config)#ip access-list standard MULTICAST_SCOPE
R2(config-std-nacl)#deny 239.0.0.0 0.255.255.255
R2(config-std-nacl)#permit any
R2(config-std-nacl)#exit

Step 2: Apply the multicast boundary at the appropriate interfaces as shown in the example below.

R2(config)#int g1/2
R2(config-if)#ip multicast boundary MULTICAST_SCOPE
R2(config-if)#end'
  impact 0.3
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-17859r287241_chk'
  tag severity: 'low'
  tag gid: 'V-216624'
  tag rid: 'SV-216624r531085_rule'
  tag stig_id: 'CISC-RT-000810'
  tag gtitle: 'SRG-NET-000019-RTR-000005'
  tag fix_id: 'F-17855r287242_fix'
  tag 'documentable'
  tag legacy: ['SV-105785', 'V-96647']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
