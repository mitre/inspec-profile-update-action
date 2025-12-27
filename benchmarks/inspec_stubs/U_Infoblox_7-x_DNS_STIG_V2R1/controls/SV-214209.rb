control 'SV-214209' do
  title 'In a split DNS configuration, where separate name servers are used between the external and internal networks, the external name server must be configured to not be reachable from inside resolvers.'
  desc 'Instead of having the same set of authoritative name servers serve different types of clients, an enterprise could have two different sets of authoritative name servers. 

One set, called external name servers, can be located within a DMZ; these would be the only name servers that are accessible to external clients and would serve RRs pertaining to hosts with public services (Web servers that serve external Web pages or provide B2C services, mail servers, etc.) 

The other set, called internal name servers, is to be located within the firewall and should be configured so they are not reachable from outside and hence provide naming services exclusively to internal clients.'
  desc 'check', 'Validation of this configuration item requires review of the network architecture and security configuration in addition to DNS server configuration to validate external name servers are not accessible from the internal network when a split DNS configuration is implemented.

Navigate to Data Management >> DNS >> Members/Servers tab.

Review both the network configuration, and access control of each Infoblox member which has the DNS service running.

Select each grid member and click "Edit".

Review the "Queries" tab to ensure both queries and recursion options are enabled and allowed only from the respective client networks.

If a split DNS configuration is not utilized, this is not a finding.

If there is no access control configured or access control does not restrict queries and recursion to the respective client network, this is a finding.'
  desc 'fix', 'Navigate to Data Management >> DNS >> Members/Servers tab.

Select each grid member and click "Edit".
Enable and configure either an Access Control List (ACL) or Set of Access Control Entries (ACE).
When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15424r295890_chk'
  tag severity: 'medium'
  tag gid: 'V-214209'
  tag rid: 'SV-214209r612370_rule'
  tag stig_id: 'IDNS-7X-000800'
  tag gtitle: 'SRG-APP-000516-DNS-000092'
  tag fix_id: 'F-15422r295891_fix'
  tag 'documentable'
  tag legacy: ['SV-83103', 'V-68613']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
