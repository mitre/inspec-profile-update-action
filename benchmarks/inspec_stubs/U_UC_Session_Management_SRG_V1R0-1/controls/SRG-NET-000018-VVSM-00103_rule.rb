control 'SRG-NET-000018-VVSM-00103_rule' do
  title 'The Unified Communications Session Manager must be configured to use DNS servers assigned to support the VVoIP system.'
  desc 'In some cases a VVoIP endpoint will be configured with one or more URLs pointing to the locations of various servers with which they are associated such as their call controller. These URLs are translated to IP addresses by a DNS server. The use of URLs in this manner permits an endpoint to find the server it is looking for in the event the server’s IP address is changed. This also permits the endpoint to locate its assigned or home call controller from a remote location on a network that is not their home network. While all of this adds flexibility to the system and the endpoint’s location, it also exposes the endpoint and the home system to DNS vulnerabilities. Additionally, the home VVoIP system must expose critical IP address and domain information to the DNS system. If the DNS system is exposed to the DNS servers that support the enterprise data network or the internet, this information and exposure of the system is, or may be, extended to the world. This provides information that can be used to attack or compromise the VVoIP system. 

When using DNS within a VVoIP system so that endpoints can find various servers in the network, the DNS server should be dedicated to the VVoIP system. Furthermore, this DNS server should have limited or no interaction with the DNS server used by the data portion of the LAN/CAN or a publicly accessible DNS server. This will protect the VVoIP system’s DNS server from some of the vulnerabilities inherent in DNS servers that serve data endpoints and that are connected to the wider enterprise networks or the internet.

While the use of DNS adds IP addressing flexibility to a VVoIP system, it is not necessary to use it for systems within the local LAN. VVoIP servers and infrastructure devices are required to be statically addressed. Therefore, the endpoints can be configured with these known IP addresses rather than URLs. A remote endpoint is required to connect to the home enclave via a VPN. It receives an internal LAN address and therefore becomes a part of the LAN and can directly reach its servers using their IP address. A URL is not required. The only time a URL might be required is in the event the endpoint is required to find a server such as a directory server that is somewhere on the WAN. This is the case in the VoSIP system on SIPRNet. Not using DNS in a VVoIP system eliminates its exposure to DNS vulnerabilities and attacks effected using information obtained from the DNS. 

NOTE: In the event a DNS server is implemented within the VVoIP system, the DNS STIG must be applied to the server.'
  desc 'check', 'Examine the configurations of the DNS server(s) serving the VVoIP system and those outside the system. Attempt to use a system specific URL that should not be published outside the system to see if an IP address is returned.

This is a finding in the event restricted URLs are reachable from outside the restriction zone.'
  desc 'fix', 'Consider not using DNS for the VVoIP system unless it is required. 

In the event DNS is used in the VVoIP system, ensure the DNS server serving the VVoIP system is dedicated to the VVoIP system and that any DNS server interaction with other DNS servers is limited. Additionally ensure internal system URLs and information is not published to the enterprise WAN or the internet.

NOTE: In the event a DNS server is implemented within the VVoIP system, the DNS STIG must be applied to the server.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000018-VVSM-00103_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000018-VVSM-00103'
  tag rid: 'SRG-NET-000018-VVSM-00103_rule'
  tag stig_id: 'SRG-NET-000018-VVSM-00103'
  tag gtitle: 'SRG-NET-000018-VVSM-00103'
  tag fix_id: 'F-SRG-NET-000018-VVSM-00103_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
