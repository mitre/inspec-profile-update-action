control 'SV-214185' do
  title 'Recursion must be disabled on Infoblox DNS servers which are configured as authoritative name servers.'
  desc "A potential vulnerability of DNS is that an attacker can poison a name server's cache by sending queries that will cause the server to obtain host-to-IP address mappings from bogus name servers that respond with incorrect information. Once a name server has been poisoned, legitimate clients may be directed to non-existent hosts (which constitutes a denial of service), or, worse, hosts that masquerade as legitimate ones to obtain sensitive data or passwords. 

To guard against poisoning, name servers authoritative for .mil domains should be separated functionally from name servers that resolve queries on behalf of internal clients. Organizations may achieve this separation by dedicating machines to each function or, if possible, by running two instances of the name server software on the same machine: one for the authoritative function and the other for the resolving function. In this design, each name server process may be bound to a different IP address or network interface to implement the required segregation.

DNSSEC ensures that the answer received when querying for name resolution actually comes from a trusted name server. Since DNSSEC is still far from being globally deployed external to DoD, and many resolvers either have not been updated or do not support DNSSEC, maintaining cached zone data separate from authoritative zone data mitigates the gap until all DNS data is validated with DNSSEC. 

Since DNS forwarding of queries can be accomplished in some DNS applications without caching locally, DNS forwarding is the method to be used when providing external DNS resolution to internal clients."
  desc 'check', 'Navigate to Data Management >> DNS >> Members/Servers tab.

Select each grid member and click "Edit".
Review the "Queries" tab.
When complete, click "Cancel" to exit the "Properties" screen.

If recursion is not disabled on an authoritative name server, this is a finding.'
  desc 'fix', 'Navigate to Data Management >> DNS >> Members/Servers tab.

Select each grid member and click "Edit".
Select the "Queries" tab and disable recursion on all authoritative members.
When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15400r295818_chk'
  tag severity: 'medium'
  tag gid: 'V-214185'
  tag rid: 'SV-214185r612370_rule'
  tag stig_id: 'IDNS-7X-000440'
  tag gtitle: 'SRG-APP-000383-DNS-000047'
  tag fix_id: 'F-15398r295819_fix'
  tag 'documentable'
  tag legacy: ['V-68565', 'SV-83055']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
