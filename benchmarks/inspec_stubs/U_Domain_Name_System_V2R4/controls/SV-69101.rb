control 'SV-69101' do
  title 'The DNS implementation must prohibit recursion on authoritative name servers.'
  desc "A potential vulnerability of DNS is that an attacker can poison a name server's cache by sending queries that will cause the server to obtain host-to-IP address mappings from bogus name servers that respond with incorrect information. Once a name server has been poisoned, legitimate clients may be directed to non-existent hosts (which constitutes a denial of service), or, worse, hosts that masquerade as legitimate ones to obtain sensitive data or passwords. 

To guard against poisoning, name servers authoritative for .mil domains should be separated functionally from name servers that resolve queries on behalf of internal clients. Organizations may achieve this separation by dedicating machines to each function or, if possible, by running two instances of the name server software on the same machine: one for the authoritative function and the other for the resolving function. In this design, each name server process may be bound to a different IP address or network interface to implement the required segregation.

DNSSEC ensures that the answer received when querying for name resolution actually comes from a trusted name server. Since DNSSEC is still far from being globally deployed external to DoD, and many resolvers either haven’t been updated or don’t support DNSSEC, maintaining cached zone data separate from authoritative zone data mitigates the gap until all DNS data is validated with DNSSEC. 

Since DNS forwarding of queries can be accomplished in some DNS applications without caching locally, DNS forwarding is the method to be used when providing external DNS resolution to internal clients."
  desc 'check', 'Review the DNS server configuration to determine if recursion is being performed on an authoritative name server. If an authoritative name server also performs recursion, this is a finding.'
  desc 'fix', 'Ensure the DNS server is not defined as both authoritative and recursive.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55477r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54855'
  tag rid: 'SV-69101r2_rule'
  tag stig_id: 'SRG-APP-000383-DNS-000047'
  tag gtitle: 'SRG-APP-000383-DNS-000047'
  tag fix_id: 'F-59713r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
