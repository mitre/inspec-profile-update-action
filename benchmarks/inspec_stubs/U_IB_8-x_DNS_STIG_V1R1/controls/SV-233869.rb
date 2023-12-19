control 'SV-233869' do
  title 'In a split DNS configuration, where separate name servers are used between the external and internal networks, the external name server must be configured to not be reachable from inside resolvers.'
  desc 'Instead of having the same set of authoritative name servers serve different types of clients, an enterprise could have two different sets of authoritative name servers. 

One set, called external name servers, can be located within a DMZ; these would be the only name servers that are accessible to external clients and would serve resource records (RRs) pertaining to hosts with public services (web servers that serve external web pages or provide B2C services, mail servers, etc.) 

The other set, called internal name servers, is to be located within the firewall and should be configured so it is not reachable from outside and hence provides naming services exclusively to internal clients.'
  desc 'check', 'Validation of this configuration item requires review of the network architecture and security configuration in addition to DNS server configuration to verify that external name servers are not accessible from the internal network when a split DNS configuration is implemented. 

1. Navigate to Data Management >> DNS >> Members tab. 
2. Review the network configuration and access control of each Infoblox member that has the DNS service running. 
3. Select each grid member and click "Edit". Review the "Queries" tab to verify that both queries and recursion options are enabled and allowed only from the respective client networks. 

If a split DNS configuration is not used, this is not a finding.  

If there is no access control configured or access control does not restrict queries and recursion to the respective client network, this is a finding.'
  desc 'fix', '1. Navigate to Data Management >> DNS >> Members tab. 
2. Select the Grid member identified as running the DNS service and click "Edit".  
3. Enable and configure either an Access Control List (ACL) or set of Access Control Entries (ACE). 
4. When complete, click "Save & Close" to save the changes and exit the "Properties" screen.  
5. Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37054r611127_chk'
  tag severity: 'medium'
  tag gid: 'V-233869'
  tag rid: 'SV-233869r621666_rule'
  tag stig_id: 'IDNS-8X-400011'
  tag gtitle: 'SRG-APP-000516-DNS-000092'
  tag fix_id: 'F-37019r611128_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
