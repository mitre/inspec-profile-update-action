control 'SV-207584' do
  title 'On a BIND 9.x server in a split DNS configuration, where separate name servers are used between the external and internal networks, the external name server must be configured to not be reachable from inside resolvers.'
  desc 'Instead of having the same set of authoritative name servers serve different types of clients, an enterprise could have two different sets of authoritative name servers. 

One set, called external name servers, can be located within a DMZ; these would be the only name servers that are accessible to external clients and would serve RRs pertaining to hosts with public services (Web servers that serve external Web pages or provide B2C services, mail servers, etc.) 

The other set, called internal name servers, is to be located within the firewall and should be configured so they are not reachable from outside and hence provide naming services exclusively to internal clients.'
  desc 'check', 'If the BIND 9.x name server is not configured for split DNS, this is Not Applicable.

Verify that the external view of the BIND 9.x server is configured to only serve external hosts.

Inspect the "named.conf" file for the following:

view "external" {
match-clients { <ip_address> | <address_match_list>; };
};

If the "match-clients" sub statement does not limit the external view to external hosts only, this is a finding.'
  desc 'fix', 'Edit the "named.conf" file.

Configure the external view statement to server external hosts only:

view "external" {
match-clients { <ip_address> | <address_match_list>; };
};

Restart the BIND 9.x process.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7839r283806_chk'
  tag severity: 'medium'
  tag gid: 'V-207584'
  tag rid: 'SV-207584r612253_rule'
  tag stig_id: 'BIND-9X-001401'
  tag gtitle: 'SRG-APP-000516-DNS-000092'
  tag fix_id: 'F-7839r283807_fix'
  tag 'documentable'
  tag legacy: ['SV-87109', 'V-72485']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
