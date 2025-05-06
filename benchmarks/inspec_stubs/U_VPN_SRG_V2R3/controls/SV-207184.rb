control 'SV-207184' do
  title 'The VPN Gateway must ensure inbound and outbound traffic is configured with a security policy in compliance with information flow control policies.'
  desc 'Unrestricted traffic may contain malicious traffic which poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

VPN traffic received from another enclave with different security policy or level of trust must not bypass be inspected by the firewall before being forwarded to the private network.'
  desc 'check', 'Verify the VPN Gateway has an inbound and outbound traffic security policy which is in compliance with information flow control policies (e.g., IPsec policy configuration).

Review network device configurations and topology diagrams. Verify encapsulated or encrypted traffic received from other enclaves with different security policies terminate at the perimeter for filtering and content inspection by a firewall and IDPS before gaining access to the private network.

If the IPsec VPN Gateway does not use Encapsulating Security Payload (ESP) in tunnel mode for establishing secured paths to transport traffic between the organizations sites or between a gateway and remote end-stations, this is a finding,'
  desc 'fix', 'Configure the VPN Gateway to ensure inbound and outbound traffic is configured with a security policy in compliance with information flow control policies (e.g., IPsec policy configuration). Also, configure the VPN gateway to forward encapsulated or encrypted traffic received from other enclaves with different security policies to the perimeter firewall and IDPS before traffic is passed to the private network.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7444r695316_chk'
  tag severity: 'medium'
  tag gid: 'V-207184'
  tag rid: 'SV-207184r695317_rule'
  tag stig_id: 'SRG-NET-000019-VPN-000040'
  tag gtitle: 'SRG-NET-000019'
  tag fix_id: 'F-7444r378174_fix'
  tag 'documentable'
  tag legacy: ['V-97041', 'SV-106179']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
