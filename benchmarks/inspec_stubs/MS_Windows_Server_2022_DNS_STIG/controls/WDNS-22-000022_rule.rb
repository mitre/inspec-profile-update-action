control 'WDNS-22-000022_rule' do
  title 'In a split DNS configuration between the external and internal networks, the external name server must be configured to not be reachable from inside resolvers.'
  desc 'Instead of having the same set of authoritative name servers serve different types of clients, an enterprise could have two different sets of authoritative name servers. 

One set, called external name servers, can be located within a DMZ; these would be the only name servers that are accessible to external clients and would serve resource records (RRs) pertaining to hosts with public services (web servers that serve external web pages or provide business-to-consumer services, mail servers, etc.).

The other set, called internal name servers, is to be located within the firewall and should be configured so the servers are not reachable from outside and hence provide naming services exclusively to internal clients.'
  desc 'check', "Consult with the system administrator to review the external Windows DNS Server's DOD approved firewall policy.

The inbound TCP and UDP ports 53 rule should be configured to only restrict IP addresses from the internal network.

If the DOD-approved firewall policy is not configured with the restriction, consult with the network firewall administrator to confirm the restriction on the network firewall.

If neither the DNS server's DOD approved firewall policy nor the network firewall is configured to block internal hosts from querying the external DNS server, this is a finding."
  desc 'fix', "Configure the external DNS server's firewall policy, or the network firewall, to block queries from internal hosts."
  impact 0.5
  tag check_id: 'C-WDNS-22-000022_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000022'
  tag rid: 'WDNS-22-000022_rule'
  tag stig_id: 'WDNS-22-000022'
  tag gtitle: 'SRG-APP-000516-DNS-000092'
  tag fix_id: 'F-WDNS-22-000022_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
