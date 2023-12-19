control 'SV-215587' do
  title 'In a split DNS configuration, where separate name servers are used between the external and internal networks, the internal name server must be configured to not be reachable from outside resolvers.'
  desc 'Instead of having the same set of authoritative name servers serve different types of clients, an enterprise could have two different sets of authoritative name servers.

One set, called external name servers, can be located within a DMZ; these would be the only name servers that are accessible to external clients and would serve RRs pertaining to hosts with public services (Web servers that serve external Web pages or provide B2C services, mail servers, etc.)

The other set, called internal name servers, is to be located within the firewall and should be configured so they are not reachable from outside and hence provide naming services exclusively to internal clients.'
  desc 'check', "Consult with the System Administrator to review the internal Windows DNS Server's HBSS firewall policy.

The inbound TCP and UDP ports 53 rule should be configured to only allow hosts from the internal network to query the internal DNS server.

If the HBSS firewall policy is not configured with the restriction, consult with the network firewall administrator to confirm the restriction on the network firewall.

If neither the DNS server's HBSS firewall policy nor the network firewall is configured to block external hosts from querying the internal DNS server, this is a finding."
  desc 'fix', "Configure the internal DNS server's firewall policy, or the network firewall, to block queries from external hosts."
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16781r314236_chk'
  tag severity: 'medium'
  tag gid: 'V-215587'
  tag rid: 'SV-215587r561297_rule'
  tag stig_id: 'WDNS-CM-000018'
  tag gtitle: 'SRG-APP-000516-DNS-000093'
  tag fix_id: 'F-16779r314237_fix'
  tag 'documentable'
  tag legacy: ['SV-73037', 'V-58607']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
