control 'SV-215586' do
  title 'In a split DNS configuration, where separate name servers are used between the external and internal networks, the external name server must be configured to not be reachable from inside resolvers.'
  desc 'Instead of having the same set of authoritative name servers serve different types of clients, an enterprise could have two different sets of authoritative name servers. 

One set, called external name servers, can be located within a DMZ; these would be the only name servers that are accessible to external clients and would serve RRs pertaining to hosts with public services (Web servers that serve external Web pages or provide B2C services, mail servers, etc.) 

The other set, called internal name servers, is to be located within the firewall and should be configured so they are not reachable from outside and hence provide naming services exclusively to internal clients.'
  desc 'check', "Consult with the System Administrator to review the external Windows DNS Server's HBSS firewall policy.

The inbound TCP and UDP ports 53 rule should be configured to only restrict IP addresses from the internal network.

If the HBSS firewall policy is not configured with the restriction, consult with the network firewall administrator to confirm the restriction on the network firewall.

If neither the DNS server's HBSS firewall policy nor the network firewall is configured to block internal hosts from querying the external DNS server, this is a finding."
  desc 'fix', "Configure the external DNS server's firewall policy, or the network firewall, to block queries from internal hosts."
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16780r314233_chk'
  tag severity: 'medium'
  tag gid: 'V-215586'
  tag rid: 'SV-215586r561297_rule'
  tag stig_id: 'WDNS-CM-000017'
  tag gtitle: 'SRG-APP-000516-DNS-000092'
  tag fix_id: 'F-16778r314234_fix'
  tag 'documentable'
  tag legacy: ['SV-73035', 'V-58605']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
