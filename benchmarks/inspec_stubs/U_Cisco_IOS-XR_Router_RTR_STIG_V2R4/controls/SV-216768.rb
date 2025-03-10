control 'SV-216768' do
  title 'The Cisco out-of-band management (OOBM) gateway router must be configured to transport management traffic to the Network Operations Center (NOC) via dedicated circuit, MPLS/VPN service, or IPsec tunnel.'
  desc 'Using dedicated paths, the OOBM backbone connects the OOBM gateway routers located at the edge of the managed network and at the NOC. Dedicated links can be deployed using provisioned circuits or MPLS Layer 2 and Layer 3 VPN services or implementing a secured path with gateway-to-gateway IPsec tunnels. The tunnel mode ensures that the management traffic will be logically separated from any other traffic traversing the same path.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the network topology diagram to determine connectivity between the managed network and the NOC. Review the OOBM gateway router configuration to validate the path and interface that the management traffic traverses. If an IPsec tunnel is used to transport the management traffic between the NOC and the managed network, review the configuration following the steps below.

Step 1: Note the profile referenced for the IPsec tunnel to the NOC

interface tunnel-ipsec 30
 profile IPSEC_NOC_PROFILE
 tunnel source GigabitEthernet0/0/0/2
 tunnel destination x.1.22.2

Step 2: Note the crypto ACL that was specified in the IPsec profile

 crypto isakmp keyring ISAKMP_KEYRING
 pre-shared-key address x.1.22.2 255.255.255.255 key encrypted 150A13141C32
!
crypto isakmp policy 10
 hash sha256
 encryption aes 256
 authentication pre-share
!
crypto ipsec transform-set IPSEC_TRANS esp-aes 256 esp-sha256-hmac
 mode tunnel
!
crypto ipsec profile IPSEC_NOC_PROFILE
 set pfs group16
 match address MGMT_TRAFFIC_ACL

Step 3: Review the ACL defined in the crypto map and verify that the destination is the management network.

!
ipv4 access-list MGMT_TRAFFIC_ACL
 10 permit ipv4 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255
!

Note: The management network is this example is 10.22.2.0/24

If management traffic is not transported between the managed network and the NOC via dedicated circuit, MPLS/VPN service, or IPsec tunnel, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Ensure that a dedicated circuit, MPLS/VPN service, or IPsec tunnel is deployed to transport management traffic between the managed network and the NOC. If an IPsec tunnel is to be used, the steps below can be used as a guideline.

Step 1: Configure the ACL for the management network as the destination. This ACL will be defined in the crypto as the interesting traffic to be forwarded into the IPsec tunnel.

RP/0/0/CPU0:R3(config)#Ipv4 access-list MGMT_TRAFFIC_ACL
RP/0/0/CPU0:R3(config-ipv4-acl)#permit ip 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255

Step 2: Create an ISAKMP policy for Phase 1 negotiations.

RP/0/0/CPU0:R3(config)#crypto isakmp policy 10
RP/0/0/CPU0:R3(config-isakmp-policy)#authentication pre-share
RP/0/0/CPU0:R3(config-isakmp-policy)#hash sha256
RP/0/0/CPU0:R3(config-isakmp-policy)#encryption aes 256
RP/0/0/CPU0:R3(config-isakmp-policy)#exit

Step 3: Configure the keyring to be used for ISAKMP to authenticate the remote side during IKE negotiation.

RP/0/0/CPU0:R3(config)#crypto isakmp keyring ISAKMP_KEYRING
RP/0/0/CPU0:R3(config-crypto-keyring)#pre-shared-key address 255.255.255.255 key xxxxx
RP/0/0/CPU0:R3(config-crypto-keyring)#exit

Step 4: Configure the IPsec transform set.

RP/0/0/CPU0:R3(config)#crypto ipsec transform-set IPSEC_TRANS esp-aes 256 esp-sha256-hmac
RP/0/0/CPU0:R3(config-transform-set IPSEC_TRANS)#mode tunnel

Step 5:  Configure the IPsec profile.

RP/0/0/CPU0:R3(config)#crypto ipsec profile IPSEC_NOC_PROFILE
RP/0/0/CPU0:R3(config- IPSEC_NOC_PROFILE)#set pfs group 16
RP/0/0/CPU0:R3(config- IPSEC_NOC_PROFILE)#match MGMT_TRAFFIC_ACL transform-set IPSEC_TRANS
RP/0/0/CPU0:R3(config- IPSEC_NOC_PROFILE)#exit

Step 6: Configure the IPsec virtual interface.
 
RP/0/0/CPU0:R3(config)#interface tunnel-ipsec 22
RP/0/0/CPU0:R3(config-if)#profile IPSEC_NOC_PROFILE
RP/0/0/CPU0:R3(config-if)#tunnel source GigabitEthernet0/0/0/2
RP/0/0/CPU0:R3(config-if)#tunnel destination x.1.22.2
RP/0/0/CPU0:R3(config-if)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18000r288687_chk'
  tag severity: 'medium'
  tag gid: 'V-216768'
  tag rid: 'SV-216768r531087_rule'
  tag stig_id: 'CISC-RT-000400'
  tag gtitle: 'SRG-NET-000205-RTR-000009'
  tag fix_id: 'F-17998r288688_fix'
  tag 'documentable'
  tag legacy: ['SV-105881', 'V-96743']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
