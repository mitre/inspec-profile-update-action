control 'SV-216774' do
  title 'The Cisco router providing connectivity to the Network Operations Center (NOC) must be configured to forward all in-band management traffic via an IPsec tunnel.'
  desc 'When the production network is managed in-band, the management network could be housed at a NOC that is located remotely at single or multiple interconnected sites. NOC interconnectivity, as well as connectivity between the NOC and the managed network, must be enabled using IPsec tunnels to provide the separation and integrity of the managed traffic.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Verify that all traffic from the managed network to the management network or NOC and vice-versa is secured via IPsec tunnel.

Step 1: Note the profile referenced for the IPSec tunnel to the NOC.

interface tunnel-ipsec 30
 profile IPSEC_NOC_PROFILE
 tunnel source GigabitEthernet0/0/0/2
 tunnel destination x.1.22.2

Step 2: Note the crypto ACL that was specified in the IPSec profile.

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

Note: The management network is this example is 10.22.2.0/24.

If the management traffic is not secured via IPsec tunnel, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Ensure that all traffic from the managed network to the management network is secured via IPsec tunnel as shown in the configuration examples below.

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

Step 4: Configure the IPSec transform set.

RP/0/0/CPU0:R3(config)#crypto ipsec transform-set IPSEC_TRANS esp-aes 256 esp-sha256-hmac
RP/0/0/CPU0:R3(config-transform-set IPSEC_TRANS)#mode tunnel

Step 5:  Configure the IPSec profile.

 RP/0/0/CPU0:R3(config)#crypto ipsec profile IPSEC_NOC_PROFILE
RP/0/0/CPU0:R3(config- IPSEC_NOC_PROFILE)#set pfs group 16
RP/0/0/CPU0:R3(config- IPSEC_NOC_PROFILE)#match MGMT_TRAFFIC_ACL transform-set IPSEC_TRANS
RP/0/0/CPU0:R3(config- IPSEC_NOC_PROFILE)#exit

Step 6: Configure the IPSec virtual interface.
 
RP/0/0/CPU0:R3(config)#interface tunnel-ipsec 22
RP/0/0/CPU0:R3(config-if)#profile IPSEC_NOC_PROFILE
RP/0/0/CPU0:R3(config-if)#tunnel source GigabitEthernet0/0/0/2
RP/0/0/CPU0:R3(config-if)#tunnel destination x.1.22.2
RP/0/0/CPU0:R3(config-if)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18006r288705_chk'
  tag severity: 'medium'
  tag gid: 'V-216774'
  tag rid: 'SV-216774r531087_rule'
  tag stig_id: 'CISC-RT-000460'
  tag gtitle: 'SRG-NET-000205-RTR-000013'
  tag fix_id: 'F-18004r288706_fix'
  tag 'documentable'
  tag legacy: ['SV-105893', 'V-96755']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
