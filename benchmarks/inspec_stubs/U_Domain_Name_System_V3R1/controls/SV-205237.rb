control 'SV-205237' do
  title 'In a split DNS configuration, where separate name servers are used between the external and internal networks, the external name server must be configured to not be reachable from inside resolvers.'
  desc 'Instead of having the same set of authoritative name servers serve different types of clients, an enterprise could have two different sets of authoritative name servers. 

One set, called external name servers, can be located within a DMZ; these would be the only name servers that are accessible to external clients and would serve RRs pertaining to hosts with public services (Web servers that serve external Web pages or provide B2C services, mail servers, etc.) 

The other set, called internal name servers, is to be located within the firewall and should be configured so they are not reachable from outside and hence provide naming services exclusively to internal clients.'
  desc 'check', 'Review the DNS implementation and ensure the external DNS name servers are not reachable by internal resolvers.

If the external DNS name servers can be reached by internal resolvers, this is a finding.'
  desc 'fix', 'Configure the DNS configuration on internal name servers to only accept queries from internal resolvers.
Configure DNS configuration on external name servers to only accept queries from external resolvers. 
Configure network perimeter devices to block query resolution traffic from external resolvers to internal name servers and from internal resolvers to external name servers.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5504r392624_chk'
  tag severity: 'medium'
  tag gid: 'V-205237'
  tag rid: 'SV-205237r879887_rule'
  tag stig_id: 'SRG-APP-000516-DNS-000092'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-5504r392625_fix'
  tag 'documentable'
  tag legacy: ['SV-69181', 'V-54935']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
