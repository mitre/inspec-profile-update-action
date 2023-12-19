control 'SV-256000' do
  title 'The Arista multicast edge router must be configured to establish boundaries for administratively scoped multicast traffic.'
  desc 'If multicast traffic is forwarded beyond the intended boundary, it is possible that it can be intercepted by unauthorized or unintended personnel.

Administrative scoped multicast addresses are locally assigned and are to be used exclusively by the enterprise network or enclave. Administrative scoped multicast traffic must not cross the enclave perimeter in either direction. Restricting multicast traffic makes it more difficult for a malicious user to access sensitive traffic.

Admin-Local scope is encouraged for any multicast traffic within a network intended for network management, as well as for control plane traffic that must reach beyond link-local destinations.'
  desc 'check', 'Review the Arista router configuration and verify that admin-scope multicast traffic is blocked at the external edge.

Step 1: Verify the Arista router ACL is configured to deny packets with multicast administratively scoped destination addresses and verify IP access lists are configured. Execute the command "show ip access-lists".

ip access-list standard mbac1
 10 deny 239.120.10.0/24
 20 permit 224.0.0.0/4
 exit

Step 2: Verify the ACL is applied on the multicast boundary at the appropriate interfaces and verify interfaces are configured. Execute the command "show run int YY".

interface vlan 200
 multicast ipv4 boundary mbac1 out
 exit

If the Arista router is not configured to establish boundaries for administratively scoped multicast traffic, this is a finding.'
  desc 'fix', 'Step 1: Configure the Arista router ACL to deny packets with multicast administratively scoped destination addresses.

router(config)#ip access-list standard mbac1
router(config-std-acl-mbac1)#10 deny 239.120.10.0/24
router(config-std-acl-mbac1)#20 permit 224.0.0.0/4
router(config-std-acl-mbac1)#exit

Step 2: Apply the multicast boundary at the appropriate interfaces.

router(config)#interface vlan 200
router(config-if-Vl200)#multicast ipv4 boundary mbac1 out
router(config-if-Vl200)#exit'
  impact 0.3
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59676r882340_chk'
  tag severity: 'low'
  tag gid: 'V-256000'
  tag rid: 'SV-256000r882342_rule'
  tag stig_id: 'ARST-RT-000140'
  tag gtitle: 'SRG-NET-000019-RTR-000005'
  tag fix_id: 'F-59619r882341_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
