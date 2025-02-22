control 'SV-207164' do
  title 'The perimeter router must be configured to block inbound packets with source Bogon IP address prefixes.'
  desc "Bogons include IP packets on the public Internet that contain addresses that are not in any range allocated or delegated by the Internet Assigned Numbers Authority (IANA) or a delegated regional Internet registry (RIR) and allowed for public Internet use. Bogons also include multicast, IETF reserved, and special purpose address space as defined in RFC 6890.
Security of the Internet's routing system relies on the ability to authenticate an assertion of unique control of an address block. Measures to authenticate such assertions rely on the validation the address block forms as part of an existing allocated address block, and must be a trustable and unique reference in the IANA address registries. The intended use of a Bogon address would only be for the purpose of address spoofing in denial-of-service attacks. Hence, it is imperative that IP packets with a source Bogon address are blocked at the network’s perimeter."
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Verify that the ingress filter is blocking packets with Bogon source addresses. 

Review the router configuration to verify that it is configured to block IP packets with a Bogon source address.

IPv4 Bogon Prefixes

0.0.0.0/8
10.0.0.0/8
100.64.0.0/10
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
192.0.0.0/24
192.0.2.0/24  
192.88.99.0/24
192.168.0.0/16
198.18.0.0/15 |
198.51.100.0/24
203.0.113.0/24 
224.0.0.0/4 
240.0.0.0/4


IPv6 Bogon Prefixes

::/128
::1/128
0::/96
::ffff:0:0/96 
3ffe::/16 
64:ff9b::/96  
100::/64   
2001:10::/28   
2001:db8::/32   
2001:2::/48  
2001::/32  
2001::/23 
2002::/16   
fc00::/7 
fec0::/10  
ff00::/8
 
    
If the router is not configured to block inbound IP packets containing a Bogon source address, this is a finding.

Note: At a minimum, IP packets containing a source address from the special purpose address space as defined in RFC 6890 must be blocked. The 6Bone prefix (3ffe::/16) is also be considered a Bogon address. Perimeter routers connected to commercial ISPs for Internet or other non-DoD network sources will need to be reviewed for a full Bogon list. 

The IPv4 full Bogon list contains prefixes that have been allocated to RIRs but not assigned by those RIRs. Reference the following link: http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt

The IPv6 full Bogon list contains prefixes that have not been allocated to RIRs, or those that have been allocated to RIRs but have not been assigned by those RIRs. Reference the following link: https://www.team-cymru.org/Services/Bogons/fullbogons-ipv6.txt'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone. 

Configure the router to block inbound packets with Bogon source addresses.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7425r648770_chk'
  tag severity: 'medium'
  tag gid: 'V-207164'
  tag rid: 'SV-207164r648771_rule'
  tag stig_id: 'SRG-NET-000364-RTR-000110'
  tag gtitle: 'SRG-NET-000364'
  tag fix_id: 'F-7425r457792_fix'
  tag 'documentable'
  tag legacy: ['V-78239', 'SV-92945']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
