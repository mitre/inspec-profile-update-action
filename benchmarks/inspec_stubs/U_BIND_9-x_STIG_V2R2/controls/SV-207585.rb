control 'SV-207585' do
  title 'On a BIND 9.x server in a split DNS configuration, where separate name servers are used between the external and internal networks, the internal name server must be configured to not be reachable from outside resolvers.'
  desc 'Instead of having the same set of authoritative name servers serve different types of clients, an enterprise could have two different sets of authoritative name servers. 

One set, called external name servers, can be located within a DMZ; these would be the only name servers that are accessible to external clients and would serve RRs pertaining to hosts with public services (Web servers that serve external Web pages or provide B2C services, mail servers, etc.) 

The other set, called internal name servers, is to be located within the firewall and should be configured so they are not reachable from outside and hence provide naming services exclusively to internal clients.'
  desc 'check', 'If the BIND 9.x name server is not configured for split DNS, this is Not Applicable.

Verify that the BIND 9.x server is configured to use the "match-clients" sub statement to limit the reach of the internal view from the external view.

Inspect the "named.conf" file for the following:

view "internal" {
match-clients { <ip_address> | <address_match_list>; };
};

If the "match-clients" sub statement is missing for the internal view, this is a finding.

If the "match-clients" sub statement for the internal view does not limit the view to authorized hosts, this is a finding.

If any of the IP addresses defined for the "match-clients" sub statement in the internal view are assigned to external hosts, this is a finding.'
  desc 'fix', 'Edit the "named.conf" file.

Configure the internal view statement to limit use authorized internal hosts:

view "internal" {
match-clients { <ip_address> | <address_match_list>; };
};

Remove any IP address that is assigned to an external host from the internal view statement.

Restart the BIND 9.x process.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7840r283809_chk'
  tag severity: 'medium'
  tag gid: 'V-207585'
  tag rid: 'SV-207585r612253_rule'
  tag stig_id: 'BIND-9X-001402'
  tag gtitle: 'SRG-APP-000516-DNS-000093'
  tag fix_id: 'F-7840r283810_fix'
  tag 'documentable'
  tag legacy: ['SV-87111', 'V-72487']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
