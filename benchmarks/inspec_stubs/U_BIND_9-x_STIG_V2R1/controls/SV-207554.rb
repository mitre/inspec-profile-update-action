control 'SV-207554' do
  title 'A BIND 9.x server implementation must prohibit recursion on authoritative name servers.'
  desc "A potential vulnerability of DNS is that an attacker can poison a name server's cache by sending queries that will cause the server to obtain host-to-IP address mappings from bogus name servers that respond with incorrect information. Once a name server has been poisoned, legitimate clients may be directed to non-existent hosts (which constitutes a denial of service), or, worse, hosts that masquerade as legitimate ones to obtain sensitive data or passwords. 

To guard against poisoning, name servers authoritative for .mil domains should be separated functionally from name servers that resolve queries on behalf of internal clients. Organizations may achieve this separation by dedicating machines to each function or, if possible, by running two instances of the name server software on the same machine: one for the authoritative function and the other for the resolving function. In this design, each name server process may be bound to a different IP address or network interface to implement the required segregation.

DNSSEC ensures that the answer received when querying for name resolution actually comes from a trusted name server. Since DNSSEC is still far from being globally deployed external to DoD, and many resolvers either have not been updated or do not support DNSSEC, maintaining cached zone data separate from authoritative zone data mitigates the gap until all DNS data is validated with DNSSEC. 

Since DNS forwarding of queries can be accomplished in some DNS applications without caching locally, DNS forwarding is the method to be used when providing external DNS resolution to internal clients.

"
  desc 'check', 'If this is a recursive name server, this is not applicable.

Note: A recursive name server should NOT be configured as an authoritative name server for any zone.

Verify that the BIND 9.x server is configured to prohibit recursion on authoritative name servers.

Inspect the "named.conf" file for the following:

options {
recursion no;
allow-recursion {none;};
allow-query {none;};
};

If the "recursion" sub statement is missing, or set to "yes", this is a finding.

If the “allow-recursion” sub statement is missing or is not set to “none”, this is a finding.

If the "allow-query" sub statement under the "options statement" is missing or is not set to "none", this is a finding.

Verify that an "allow-query" sub statement under each zone statement is configured to authorized hosts:

zone "example.com" {
type master;
file "db.example.com";
allow-query { (address_match_list | <ip_address>) };
};

If the "allow-query" sub statement under each zone statement is not restricted to authorized hosts, this is a finding.'
  desc 'fix', 'Configure the authoritative name server to prohibit recursion.

Edit the "named.conf" file and add the following sub statements to the options statement:

recursion no;
allow-recursion {none;};
allow-query { none };

Configure each zone to limit queries to authorized hosts:

Edit the "named.conf" file and add the following sub statement to each zone definition:

allow-query { address_match_list; };

Restart the BIND 9.x process'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7809r283716_chk'
  tag severity: 'medium'
  tag gid: 'V-207554'
  tag rid: 'SV-207554r612253_rule'
  tag stig_id: 'BIND-9X-001055'
  tag gtitle: 'SRG-APP-000246-DNS-000035'
  tag fix_id: 'F-7809r283717_fix'
  tag satisfies: ['SRG-APP-000246-DNS-000035', 'SRG-APP-000383-DNS-000047']
  tag 'documentable'
  tag legacy: ['SV-87031', 'V-72407']
  tag cci: ['CCI-001094', 'CCI-000366']
  tag nist: ['SC-5 (1)', 'CM-6 b']
end
