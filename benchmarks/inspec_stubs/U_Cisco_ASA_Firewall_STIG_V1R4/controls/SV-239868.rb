control 'SV-239868' do
  title 'The Cisco ASA must be configured to forward management traffic to the Network Operations Center (NOC) via an IPsec tunnel.'
  desc 'When the production network is managed in-band, the management network could be housed at a NOC that is located remotely at single or multiple interconnected sites. NOC interconnectivity, as well as connectivity between the NOC and the managed network, must be enabled using IPsec tunnels to provide the separation and integrity of the managed traffic.'
  desc 'check', 'Step 1: Verify that an IPsec crypto map has been configured and bound to the outside interface as shown in the example below.

crypto ipsec ikev1 transform-set IPSEC_TRANSFORM esp-aes-192 esp-sha-hmac 
crypto map IPSEC_CRYPTO_MAP 1 match address MANAGEMENT_TRAFFIC
crypto map IPSEC_CRYPTO_MAP 1 set peer 10.3.1.1 
crypto map IPSEC_CRYPTO_MAP 1 set ikev1 transform-set IPSEC_TRANSFORM
crypto map IPSEC_CRYPTO_MAP 1 set security-association lifetime seconds 3600
crypto map IPSEC_CRYPTO_MAP interface OUTSIDE

Step 2: Verify the there is a tunnel group configured for the peer defined in the crypto map as shown in the example below.

tunnel-group 10.3.1.1 type ipsec-l2l
tunnel-group 10.3.1.1 ipsec-attributes
 ikev1 pre-shared-key *****

Step 3: Verify that an ISAKMP policy for IKE connections has been configured and bound to the outside interface as shown in the example.

crypto isakmp identity address 
crypto ikev1 enable OUTSIDE
crypto ikev1 policy 10
 authentication pre-share
 encryption aes-256
 hash sha
 group 5
 lifetime 3600

Step 4: Verify that the ACL referenced in the IPsec crypto map includes all applicable management traffic.

access-list MANAGEMENT_TRAFFIC extended permit udp any eq snmp 10.2.2.0 255.255.255.0 
access-list MANAGEMENT_TRAFFIC extended permit udp any eq 10.2.2.0 255.255.255.0 snmptrap
access-list MANAGEMENT_TRAFFIC extended permit udp any eq syslog 10.2.2.0 255.255.255.0 
access-list MANAGEMENT_TRAFFIC extended permit tcp any eq ssh 10.2.2.0 255.255.255.0 

Note: Exception would be allowed for management traffic to and from managed perimeter devices.

If the ASA is not configured to forward management traffic to the Network Operations Center (NOC) via an IPsec tunnel, this is a finding.'
  desc 'fix', 'Step 1: Configure an ISAKMP policy for IKE connection as shown in the example.

ASA1(config)# crypto ikev1 policy 10
ASA1(config-ikev1-policy)# authentication pre-share
ASA1(config-ikev1-policy)# encryption aes-256
ASA1(config-ikev1-policy)# hash sha
ASA1(config-ikev1-policy)# group 5
ASA1(config-ikev1-policy)# lifetime 3600
ASA1(config-ikev1-policy)# exit

Step 2: Enable the IKEv1 policy on the outside interface and identify itself with its IP address.

ASA1(config)# crypto ikev1 enable OUTSIDE
ASA1(config)# crypto isakmp identity address

Step 3: Configure the tunnel group as shown in the example below.

ASA2(config)# tunnel-group 10.10.10.1 ipsec-attributes
ASA2(config-tunnel-ipsec)# ikev1 pre-shared-key xxxxxxxxxxxxx 

Step 4: Configure a transform set for encryption and authentication.

crypto ipsec ikev1 transform-set IPSEC_TRANSFORM esp-aes-192 esp-sha-hmac

Step 5: Configure the ACL to define the management traffic that will traverse the tunnel.

ASA1(config)# access-list MANAGEMENT_TRAFFIC extended permit udp any eq snmp 10.2.2.0 255.255.255.0 
ASA1(config)# access-list MANAGEMENT_TRAFFIC extended permit udp any eq 10.2.2.0 255.255.255.0 snmptrap
ASA1(config)# access-list MANAGEMENT_TRAFFIC extended permit udp any eq syslog 10.2.2.0 255.255.255.0 
ASA1(config)# access-list MANAGEMENT_TRAFFIC extended permit tcp any eq ssh 10.2.2.0 255.255.255.0 

Step 6: Configure crypto map and bind to the outside interface as shown in the example below.

ASA1(config)# crypto map IPSEC_CRYPTO_MAP 1 match address MANAGEMENT_TRAFFIC
ASA1(config)# crypto map IPSEC_CRYPTO_MAP 1 set peer 10.10.10.2
ASA1(config)# crypto map IPSEC_CRYPTO_MAP 1 set ikev1 transform-set MY_TRANSFORM_SET
ASA1(config)# crypto map IPSEC_CRYPTO_MAP 1 set security-association lifetime seconds 3600
ASA1(config)# crypto map IPSEC_CRYPTO_MAP interface OUTSIDE'
  impact 0.5
  ref 'DPMS Target Cisco ASA Firewall'
  tag check_id: 'C-43101r665888_chk'
  tag severity: 'medium'
  tag gid: 'V-239868'
  tag rid: 'SV-239868r855810_rule'
  tag stig_id: 'CASA-FW-000260'
  tag gtitle: 'SRG-NET-000364-FW-000036'
  tag fix_id: 'F-43060r665889_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
