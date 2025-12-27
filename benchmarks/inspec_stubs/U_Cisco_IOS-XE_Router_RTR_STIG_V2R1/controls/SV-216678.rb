control 'SV-216678' do
  title 'The Cisco out-of-band management (OOBM) gateway router must be configured to transport management traffic to the Network Operations Center (NOC) via dedicated circuit, MPLS/VPN service, or IPsec tunnel.'
  desc 'Using dedicated paths, the OOBM backbone connects the OOBM gateway routers located at the edge of the managed network and at the NOC. Dedicated links can be deployed using provisioned circuits or MPLS Layer 2 and Layer 3 VPN services or implementing a secured path with gateway-to-gateway IPsec tunnels. The tunnel mode ensures that the management traffic will be logically separated from any other traffic traversing the same path.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the network topology diagram to determine connectivity between the managed network and the NOC. Review the OOBM gateway router configuration to validate the path and interface that the management traffic traverses. If an IPsec tunnel is used to transport the management traffic between the NOC and the managed network, review the configuration following the steps below.

Step 1: Note the crypto map applied to the external interface.

 interface interface GigabitEthernet0/2
 description link to DISN
 ip address x.1.24.4 255.255.255.0
 crypto map IPSEC_MGMT_MAP

Step 2: Review the ISAKMP policy for Phase 1 negotiations and Phase 2 policy for data encryption.

crypto isakmp policy 10
 authentication pre-share
 hash sha256
 crypto isakmp key xxxxxx address x.1.12.1
!
!
crypto ipsec transform-set TRANS_SET ah-sha256-hmac esp-aes 

Step 3: Review the crypto map that was bound to the external interface and note the ACL defined that identifies the interesting traffic for the IPsec tunnel.

crypto map IPSEC_MGMT_MAP 10 ipsec-isakmp
 set peer x.1.12.1
 set transform-set TRANS_SET
 match address MGMT_TRAFFIC_ACL

Step 4: Review the ACL defined in the crypto map and verify that the destination is the management network.

ip access-list extended MGMT_TRAFFIC_ACL
 permit ip 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255

Note: The management network is this example is 10.22.2.0/24

If management traffic is not transported between the managed network and the NOC via dedicated circuit, MPLS/VPN service, or IPsec tunnel, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Ensure that a dedicated circuit, MPLS/VPN service, or IPsec tunnel is deployed to transport management traffic between the managed network and the NOC.  If an IPsec tunnel is to be used, the steps below can be used as a guideline.

Step 1: Configure the ACL for the management network as the destination. This ACL will be defined in the crypto as the interesting traffic to be forwarded into the IPsec tunnel.

R4(config)#ip access-list extended MGMT_TRAFFIC_ACL
R4(config-ext-nacl)#permit ip 10.1.34.0 0.0.0.255 10.22.2.0 0.0.0.255
R4(config-ext-nacl)#exit

Step 2: Create an ISAKMP policy for Phase 1 negotiations.

R4(config)#crypto isakmp policy 10
R4(config-isakmp)#hash sha256
R4(config-isakmp)#authentication pre-share
R4(config-isakmp)#exit

Step 3: Specify the pre-shared key and the remote peer address.

R4(config)#crypto isakmp key 0 xxxxxx address x.1.12.1

Note: Digital certificates can be utilized as an alternative.
 
Step 4: Create the IPSec transform set for the data encryption.

R4(config)#crypto ipsec transform-set TRANS_SET ah-sha256-hmac esp-aes
R4(cfg-crypto-trans)#mode tunnel
R4(cfg-crypto-trans)#exit

Step 5: Create the crypto map.

R4(config)#crypto map IPSEC_MGMT_MAP 10 ipsec-isakmp
R4(config-crypto-map)#set peer x.1.12.1
R4(config-crypto-map)#match address MGMT_TRAFFIC_ACL
R4(config-crypto-map)#set transform-set TRANS_SET
R4(config-crypto-map)#end

Step 6: Apply the crypto map to the external interface. 

R4(config)#int g0/2
R4(config-if)#crypto map IPSEC_MGMT_MAP'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-17911r287985_chk'
  tag severity: 'medium'
  tag gid: 'V-216678'
  tag rid: 'SV-216678r531086_rule'
  tag stig_id: 'CISC-RT-000400'
  tag gtitle: 'SRG-NET-000205-RTR-000009'
  tag fix_id: 'F-17909r287986_fix'
  tag 'documentable'
  tag legacy: ['V-96929', 'SV-106067']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
