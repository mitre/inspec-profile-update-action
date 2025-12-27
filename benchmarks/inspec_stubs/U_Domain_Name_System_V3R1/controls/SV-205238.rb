control 'SV-205238' do
  title 'In a split DNS configuration, where separate name servers are used between the external and internal networks, the internal name server must be configured to not be reachable from outside resolvers.'
  desc 'Instead of having the same set of authoritative name servers serve different types of clients, an enterprise could have two different sets of authoritative name servers. 

One set, called external name servers, can be located within a DMZ; these would be the only name servers that are accessible to external clients and would serve RRs pertaining to hosts with public services (Web servers that serve external Web pages or provide B2C services, mail servers, etc.) 

The other set, called internal name servers, is to be located within the firewall and should be configured so they are not reachable from outside and hence provide naming services exclusively to internal clients.'
  desc 'check', 'Review the DNS implementation and ensure internal DNS name servers are not reachable by external resolvers.

If the internal DNS name servers can be reached by external resolvers, this is a finding.'
  desc 'fix', 'Configure the DNS configuration on internal name servers to only accept queries from internal resolvers.
Configure DNS configuration on external name servers to only accept queries from external resolvers. 
Configure network perimeter devices to block query resolution traffic from external resolvers to internal name servers and from internal resolvers to external name servers.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5505r392627_chk'
  tag severity: 'medium'
  tag gid: 'V-205238'
  tag rid: 'SV-205238r879887_rule'
  tag stig_id: 'SRG-APP-000516-DNS-000093'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-5505r392628_fix'
  tag 'documentable'
  tag legacy: ['SV-69183', 'V-54937']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
