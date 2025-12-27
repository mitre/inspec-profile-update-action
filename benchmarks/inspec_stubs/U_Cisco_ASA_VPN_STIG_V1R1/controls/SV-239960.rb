control 'SV-239960' do
  title 'The Cisco ASA VPN gateway must be configured to restrict what traffic is transported via the IPsec tunnel according to flow control policies.'
  desc 'Unrestricted traffic may contain malicious traffic which poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

VPN traffic received from another enclave with different security policy or level of trust must not bypass being inspected by the firewall before being forwarded to the private network.'
  desc 'check', 'Step 1: Determine the ACL that is used to define what traffic will be transported via the IPsec tunnel.

crypto map IPSEC_MAP 10 match address SITE1_SITE2
crypto map IPSEC_MAP 10 set peer x.x.x.x

Step 2: Verify that the traffic defined in the ACL is in accordance with flow control policies.

access-list SITE1_SITE2 extended permit ip 192.168.1.0 255.255.255.0 192.168.2.0 255.255.255.0

If the VPN gateway is not configured to restrict what traffic is transported via the IPsec tunnel, this is a finding.'
  desc 'fix', 'Step 1: Define what traffic will be transported via the IPsec tunnel as shown in the example below.

ASA1(config)# access-list SITE1_SITE2 extended permit ip 192.168.1.0 255.255.255.0 192.168.2.0 255.255.255.0

Step 2: Apply the ACL to the IPsec crypto map.

ASA1(config)# crypto map IPSEC_MAP 10 match address SITE1_SITE2'
  impact 0.5
  ref 'DPMS Target Cisco ASA VPN'
  tag check_id: 'C-43193r666284_chk'
  tag severity: 'medium'
  tag gid: 'V-239960'
  tag rid: 'SV-239960r666286_rule'
  tag stig_id: 'CASA-VN-000300'
  tag gtitle: 'SRG-NET-000019-VPN-000040'
  tag fix_id: 'F-43152r666285_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
