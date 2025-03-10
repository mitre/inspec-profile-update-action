control 'SV-258583' do
  title 'The ICS must be configured to ensure inbound and outbound traffic is configured with a security policy in compliance with information flow control policies.'
  desc 'Unrestricted traffic may contain malicious traffic which poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

VPN traffic received from another enclave with different security policy or level of trust must not bypass be inspected by the firewall before being forwarded to the private network.'
  desc 'check', 'In the ICS Web UI, navigate to Users >> Resource Policies >> VPN Tunneling >> Access Control.
1. Verify that an Access Control Policy exists.
2. Verify the Access Control Policy is not configured to allows all IPv4/IPv6 addresses or all TCP/UDP ports.

If the ICS does not use one or more Access Control Policies to restrict inbound and outbound traffic compliance with the sites documented information flow control policy, this is a finding.'
  desc 'fix', %q(Establish Access Control policy in accordance with the site's system security plan. Policies will vary based on security policies and architecture.

In the ICS Web UI, navigate to Users >> Resource Policies >> VPN Tunneling >> Access Control.
1. Click "New Policy".
2. Enter a name.
3. Under IPv4 Resources, add all allowed ports and protocols required for users. Examples provided below:
- For ICMP configure the following: icmp://10.0.0.0/255.255.255.0 to allow ICMP communications for the 10.0.0.0/24 subnet.
- For TCP configure the following: tcp://*:80,443 to allow TCP communications for all IPv4 addresses going to TCP port 80 and 443 (web traffic).
- For UDP configure the following: udp://10.0.0.0/255.255.255.0:53,123 to allow UDP communications for the 10.0.0.0/24 IPv4 addresses going to UDP port 53 (DNS) and 123 (NTP).
4. Under IPv6 Resources, add all allowed ports and protocols required for users. Examples provided below:
- For ICMP configure the following: icmpv6://[2001:db8:1::/64] to allow ICMPv6 communications for the 2001:db8:1::/64 subnet.
- For TCP configure the following: tcp://[*]:80,443 to allow TCP communications for all IPv6 addresses going to TCP port 80 and 443 (web traffic).
- For UDP configure the following: udp://[2001:db8:2::/64]:53,123 to allow UDP communications for the 2001:db8:2::/64 IPv6 addresses going to UDP port 53 (DNS) and 123 (NTP).
5. For FQDN, add specific URLs to allow, if needed.
6. Select "Policy applies to SELECTED roles" and select the role that remote access VPN users are assigned. If there are multiple, select each one and click "Add".
7. Click "Allow Access".
8. Click "Save Changes".)
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure VPN'
  tag check_id: 'C-62323r930435_chk'
  tag severity: 'medium'
  tag gid: 'V-258583'
  tag rid: 'SV-258583r930437_rule'
  tag stig_id: 'IVCS-VN-000010'
  tag gtitle: 'SRG-NET-000019-VPN-000040'
  tag fix_id: 'F-62232r930436_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
