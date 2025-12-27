control 'SV-233874' do
  title 'The Infoblox DNS server must use current and valid root name servers.'
  desc "All caching name servers must be authoritative for the root zone because, without this starting point, they would have no knowledge of the DNS infrastructure and thus would be unable to respond to any queries. 

An adversary could change the root hints and direct the caching name server to a bogus root server. At that point, every query response from that name server is suspect, which would give the adversary substantial control over the network communication of the name servers' clients. 

When authoritative servers are sent queries for zones for which they are not authoritative, and they are configured as a non-caching server (as recommended), they can either be configured to return a referral to the root servers or to refuse to answer the query. The recommendation is to configure authoritative servers to refuse to answer queries for any zones for which they are not authoritative. This is more efficient for the server and allows it to spend more of its resources serving its intended purpose: answering authoritatively for its zone."
  desc 'check', 'Review the Root Name Servers configured and validate that the entries are correct. "G" and "H" root servers are required on the NIPRNet as a minimum. Note: Validate against the current available DNS root list at the time of check.  

1. Validate the current root name server list using external tools at the time of the check.
2. Navigate to Data Management >> DNS >> Grid DNS Properties. 
3. Toggle Advanced mode and review the "Root Name Servers" tab to ensure it is configured correctly. 

If valid root name servers are not configured, this is a finding.'
  desc 'fix', '1. Navigate to Data Management >> DNS >> Grid DNS Properties. 
2. Toggle Advanced mode and select the "Root Name Servers" tab.  
3. Use the radio button to select "Use custom root name servers" and configure the desired root name servers.  
4. When complete, click "Save & Close" to save the changes and exit the "Properties" screen. 
5. Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37059r611142_chk'
  tag severity: 'medium'
  tag gid: 'V-233874'
  tag rid: 'SV-233874r621666_rule'
  tag stig_id: 'IDNS-8X-400016'
  tag gtitle: 'SRG-APP-000516-DNS-000102'
  tag fix_id: 'F-37024r611143_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
