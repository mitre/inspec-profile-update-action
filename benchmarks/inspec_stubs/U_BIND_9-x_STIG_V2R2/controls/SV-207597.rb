control 'SV-207597' do
  title 'On a BIND 9.x server all root name servers listed in the local root zone file hosted on a BIND 9.x authoritative name server must be valid for that zone.'
  desc "All caching name servers must be authoritative for the root zone because, without this starting point, they would have no knowledge of the DNS infrastructure and thus would be unable to respond to any queries. The security risk is that an adversary could change the root hints and direct the caching name server to a bogus root server. At that point, every query response from that name server is suspect, which would give the adversary substantial control over the network communication of the name servers' clients."
  desc 'check', 'If this is an authoritative name server, this is Not Applicable.

Identify the local root zone file in named.conf:

zone "." IN {
type hint;
file "<file_name>"
};

Examine the local root zone file.

If the local root zone file lists domains outside of the name server’s primary domain, this is a finding.'
  desc 'fix', 'Edit the local root zone file.

Remove any reference to a domain that is outside of the name server’s primary domain.

Restart the BIND 9.x process.'
  impact 0.3
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7852r283845_chk'
  tag severity: 'low'
  tag gid: 'V-207597'
  tag rid: 'SV-207597r612253_rule'
  tag stig_id: 'BIND-9X-001620'
  tag gtitle: 'SRG-APP-000516-DNS-000102'
  tag fix_id: 'F-7852r283846_fix'
  tag 'documentable'
  tag legacy: ['SV-87135', 'V-72511']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
