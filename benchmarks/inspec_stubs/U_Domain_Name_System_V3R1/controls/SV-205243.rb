control 'SV-205243' do
  title 'The DNS must utilize valid root name servers in the local root zone file.'
  desc "All caching name servers must be authoritative for the root zone because, without this starting point, they would have no knowledge of the DNS infrastructure and thus would be unable to respond to any queries. The security risk is that an adversary could change the root hints and direct the caching name server to a bogus root server. At that point, every query response from that name server is suspect, which would give the adversary substantial control over the network communication of the name servers' clients. When authoritative servers are sent queries for zones that they are not authoritative for, and they are configured as a non-caching server (as recommended), they can either be configured to return a referral to the root servers or they can be configured to refuse to answer the query. The recommendation is to configure authoritative servers to refuse to answer queries for any zones for which they are not authoritative. This is more efficient for the server and allows it to spend more of its resources doing what its intended purpose is, answering authoritatively for its zone."
  desc 'check', 'Review the entries within the root hints file and validate that the entries are correct. G and H root servers are required on the NIPRNet, as a minimum. All default settings on servers must be verified and corrected if necessary. If valid root name servers are not configured, this is a finding.'
  desc 'fix', 'Configure the DNS implementation to use valid root name servers.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5510r392642_chk'
  tag severity: 'medium'
  tag gid: 'V-205243'
  tag rid: 'SV-205243r879887_rule'
  tag stig_id: 'SRG-APP-000516-DNS-000102'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-5510r392643_fix'
  tag 'documentable'
  tag legacy: ['SV-69193', 'V-54947']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
