control 'SV-23734' do
  title 'The VVoIP system DNS server is not dedicated to the VVoIP system within the LAN; or the VVoIP system DNS server freely interacts with other DNS servers outside the VVoIP system; or the VVoIP system information is published to the enterprise WAN or the Internet.'
  desc 'In some cases a VVoIP endpoint will be configured with one or more URLs pointing to the locations of various servers with which they are associated such as their call controller. These URLs are translated to IP addresses by a DNS server. The use of URLS in this manner permits an endpoint to find the server it is looking for in the event the server’s IP address is changed. This also permits the endpoint to locate its assigned or home call controller from a remote location on a network that is not their home network. While all of this adds flexibility to the system and the endpoint’s location, it also exposes the endpoint and the home system to DNS vulnerabilities. Additionally, the home VVoIP system must expose critical IP address and domain information to the DNS system. If the DNS system is exposed to the DNS servers that support the enterprise data network or the Internet, this information and exposure of the system is, or may be, extended to the world. This provides information that can be used to attack or compromise the VVoIP system. 

When using DNS within a VVoIP system so that endpoints can find various servers in the network, the DNS server should be dedicated to the VVoIP system. Further more this DNS server should have limited or no interaction with the DNS server used by the data portion of the LAN/CAN or a publicly accessible DNS server. This will protect the VVoIP system’s DNS server from some of the vulnerabilities inherent in DNS servers that serve data endpoints and that are connected to the wider enterprise networks or the Internet.

While the use of DNS adds IP addressing flexibility to a VVoIP system, it is not necessary to use it for systems within the local LAN. VVoIP servers and infrastructure devices are required to be statically addressed. Therefore the endpoints can be configured with these known IP addresses rather than URLs. A remote endpoint is required to connect to the home enclave via a VPN. It receives an internal LAN address and therefore becomes a part of the LAN and can directly reach its servers using their IP address. A URL is not required. The only time a URL might be required is in the event the endpoint is required to find a server such as a directory server that is somewhere on the WAN. This is the case in the VoSIP system on SIPRNet. Not using DNS in a VVoIP system eliminates its exposure to DNS vulnerabilities and attacks effected using information obtained from the DNS. 

NOTE: In the event a DNS server is implemented within the VVoIP system, the DNS STIG must be applied to the server.'
  desc 'check', 'Interview the IAO to validate compliance with the following requirement:

In the event DNS is used in the VVoIP system, ensure the DNS server is dedicated to the VVoIP system and that any DNS server interaction with other DNS servers is limited. Additionally ensure internal system URLS and information is not published to the enterprise WAN or the Internet. 

Determine if: 
The VVoIP system DNS server is not dedicated to the VVoIP system within the LAN;
OR 
The VVoIP system DNS server freely interacts with other DNS servers outside the VVoIP system;
OR 
The VVoIP system information is published to the enterprise WAN or the Internet.

This is a finding in the event one or more of these conditions exist.'
  desc 'fix', 'Consider not using DNS for the VVoIP system unless it is required. 

In the event DNS is used in the VVoIP system, ensure the DNS server serving the VVoIP system is dedicated to the VVoIP system and that any DNS server interaction with other DNS servers is limited. Additionally ensure internal system URLS and information is not published to the enterprise WAN or the Internet.

NOTE: In the event a DNS server is implemented within the VVoIP system, the DNS STIG must be applied to the server.'
  impact 0.3
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-25780r1_chk'
  tag severity: 'low'
  tag gid: 'V-21522'
  tag rid: 'SV-23734r1_rule'
  tag stig_id: 'VVoIP 5212 (LAN)'
  tag gtitle: 'Deficient design: VVoIP system re: DNS'
  tag fix_id: 'F-22313r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'None'
  tag responsibility: 'Information Assurance Officer'
end
