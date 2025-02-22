control 'SV-207598' do
  title 'On a BIND 9.x server all root name servers listed in the local root zone file hosted on a BIND 9.x authoritative name server must be empty or removed.'
  desc 'A potential vulnerability of DNS is that an attacker can poison a name servers cache by sending queries that will cause the server to obtain host-to-IP address mappings from bogus name servers that respond with incorrect information. The DNS architecture needs to maintain one name server whose zone records are correct and the cache is not poisoned, in this effort the authoritative name server may not forward queries, one of the ways to prevent this, the root hints file is to be deleted.

When authoritative servers are sent queries for zones that they are not authoritative for, and they are configured as a non-caching server (as recommended), they can either be configured to return a referral to the root servers or they can be configured to refuse to answer the query. The requirement is to configure authoritative servers to refuse to answer queries for any zones for which they are not authoritative. This is more efficient for the server, and allows it to spend more of its resources doing what its intended purpose is; answering authoritatively for its zone.'
  desc 'check', 'If this server is a caching name server, this is Not Applicable.

Ensure there is not a local root zone on the name server.

Inspect the "named.conf" file for the following:

zone "." IN {
type hint;
file "<file_name>"
};

If the file name identified is not empty or does exist, this is a finding.'
  desc 'fix', 'Remove the local root zone file from the name server.'
  impact 0.3
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7853r283848_chk'
  tag severity: 'low'
  tag gid: 'V-207598'
  tag rid: 'SV-207598r612253_rule'
  tag stig_id: 'BIND-9X-001621'
  tag gtitle: 'SRG-APP-000516-DNS-000102'
  tag fix_id: 'F-7853r283849_fix'
  tag 'documentable'
  tag legacy: ['SV-87137', 'V-72513']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
