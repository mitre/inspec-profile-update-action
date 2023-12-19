control 'SV-214213' do
  title 'The Infoblox system must utilize valid root name servers in the local root zone file.'
  desc "All caching name servers must be authoritative for the root zone because, without this starting point, they would have no knowledge of the DNS infrastructure and thus would be unable to respond to any queries. The security risk is that an adversary could change the root hints and direct the caching name server to a bogus root server. At that point, every query response from that name server is suspect, which would give the adversary substantial control over the network communication of the name servers' clients. When authoritative servers are sent queries for zones that they are not authoritative for, and they are configured as a non-caching server (as recommended), they can either be configured to return a referral to the root servers or they can be configured to refuse to answer the query. The recommendation is to configure authoritative servers to refuse to answer queries for any zones for which they are not authoritative. This is more efficient for the server and allows it to spend more of its resources doing what its intended purpose is, answering authoritatively for its zone."
  desc 'check', 'Review the entries within the root hints file and validate that the entries are correct. "G" and "H" root servers are required on the NIPRNet, as a minimum. All default settings on servers must be verified and corrected if necessary.

If valid root name servers are not configured, this is a finding.

Navigate Data Management >> DNS >> Grid DNS Properties.

Toggle Advanced mode and review "Root Name Servers" tab to ensure it is configured correctly.

Note: Validate against the current available DNS root list at the time of check.'
  desc 'fix', 'Navigate Data Management >> DNS >> Grid DNS Properties.

Toggle Advanced mode and select the "Root Name Servers" tab.
Use the radio button to select "Use custom root name servers" and configure the desired root name servers.
When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15428r295902_chk'
  tag severity: 'medium'
  tag gid: 'V-214213'
  tag rid: 'SV-214213r612370_rule'
  tag stig_id: 'IDNS-7X-000850'
  tag gtitle: 'SRG-APP-000516-DNS-000102'
  tag fix_id: 'F-15426r295903_fix'
  tag 'documentable'
  tag legacy: ['SV-83135', 'V-68645']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
