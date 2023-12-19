control 'SV-216684' do
  title 'The Cisco router providing connectivity to the Network Operations Center (NOC) must be configured to forward all in-band management traffic via an IPsec tunnel.'
  desc 'When the production network is managed in-band, the management network could be housed at a NOC that is located remotely at single or multiple interconnected sites. NOC interconnectivity, as well as connectivity between the NOC and the managed network, must be enabled using IPsec tunnels to provide the separation and integrity of the managed traffic.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Verify that all traffic from the managed network to the management network or NOC and vice-versa is secured via IPsec tunnel.

Step 1: Note the crypto map applied to the external interface.

 interface GigabitEthernet0/2
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

If the management traffic is not secured via IPsec tunnel, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Ensure that all traffic from the managed network to the management network is secured via IPsec tunnel as shown in the configuration examples below.

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

R4(config)#crypto isakmp key 0 xxxxxx address 10.1.12.1

Note: Digital certificates can be utilized as an alternative.
 
Step 4: Create the Phase 2 policy for the data encryption.

R4(config)#crypto ipsec transform-set TRANS_SET ah-sha256-hmac esp-aes
R4(cfg-crypto-trans)#mode tunnel
R4(cfg-crypto-trans)#exit

Step 5: Create the crypto map.

R4(config)#crypto map IPSEC_MGMT_MAP 10 ipsec-isakmp
R4(config-crypto-map)#set peer 10.1.12.1
R4(config-crypto-map)#match address MGMT_TRAFFIC_ACL
R4(config-crypto-map)#set transform-set TRANS_SET
R4(config-crypto-map)#end

Step 6: Apply the crypto map to the external interface. 

R4(config)#int g0/2
R4(config-if)#crypto map IPSEC_MGMT_MAP'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-17917r288003_chk'
  tag severity: 'medium'
  tag gid: 'V-216684'
  tag rid: 'SV-216684r531086_rule'
  tag stig_id: 'CISC-RT-000460'
  tag gtitle: 'SRG-NET-000205-RTR-000013'
  tag fix_id: 'F-17915r288004_fix'
  tag 'documentable'
  tag legacy: ['SV-106079', 'V-96941']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
