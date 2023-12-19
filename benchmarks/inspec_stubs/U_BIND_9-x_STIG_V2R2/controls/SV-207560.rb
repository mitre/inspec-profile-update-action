control 'SV-207560' do
  title 'A BIND 9.x implementation configured as a caching name server must restrict recursive queries to only the IP addresses and IP address ranges of known supported clients.'
  desc 'Any host that can query a resolving name server has the potential to poison the servers name cache or take advantage of other vulnerabilities that may be accessed through the query service. The best way to prevent this type of attack is to limit queries to internal hosts, which need to have this service available to them.

To guard against poisoning, name servers authoritative for .mil domains should be separated functionally from name servers that resolve queries on behalf of internal clients. Organizations may achieve this separation by dedicating machines to each function or, if possible, by running two instances of the name server software on the same machine; one for the authoritative function and the other for the resolving function. In this design, each name server process may be bound to a different IP address or network interface to implement the required segregation.'
  desc 'check', 'This check is only applicable to caching name servers.

Verify the allow-query and allow-recursion phrases are properly configured.

Inspect the "named.conf" file for the following:

allow-query {trustworthy_hosts;};
allow-recursion {trustworthy_hosts;};

The name of the ACL does not need to be "trustworthy_hosts" but the name should match the ACL name defined earlier in "named.conf" for this purpose. If not, this is a finding.

Verify non-internal IP addresses do not appear in either the referenced ACL (e.g., trustworthy_hosts) or directly in the statements themselves.

If non-internal IP addresses appear, this is a finding.'
  desc 'fix', 'Configure the caching name server to accept recursive queries only from the IP addresses and address ranges of known supported clients.

Edit the "named.conf" file and add the following to the options statement:

allow-query {trustworthy_hosts;};
allow-recursion {trustworthy_hosts;}; 

Restart the BIND 9.x process'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7815r283734_chk'
  tag severity: 'medium'
  tag gid: 'V-207560'
  tag rid: 'SV-207560r612253_rule'
  tag stig_id: 'BIND-9X-001080'
  tag gtitle: 'SRG-APP-000246-DNS-000035'
  tag fix_id: 'F-7815r283735_fix'
  tag 'documentable'
  tag legacy: ['SV-87049', 'V-72425']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
