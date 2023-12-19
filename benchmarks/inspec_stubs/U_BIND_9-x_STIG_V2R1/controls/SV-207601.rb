control 'SV-207601' do
  title 'The BIND 9.x server implementation must prohibit the forwarding of queries to servers controlled by organizations outside of the U.S. Government.'
  desc 'If remote servers to which DoD DNS servers send queries are controlled by entities outside of the U.S. Government the possibility of a DNS attack is increased. 

The Enterprise Recursive Service (ERS) provides the ability to apply enterprise-wide policy to all recursive DNS traffic that traverses the NIPRNet-to-Internet boundary. All recursive DNS servers on the NIPRNet must be configured to exclusively forward DNS traffic traversing NIPRNet-to-Internet boundary to the ERS anycast IPs.

Organizations need to carefully configure any forwarding that is being used by their caching name servers. They should only configure "forwarding of all queries" to servers within the DoD. Systems configured to use domain-based forwarding should not forward queries for mission critical domains to any servers that are not under the control of the US Government.'
  desc 'check', 'If the server is not a caching server, this is Not Applicable.

Note: The use of the DREN Enterprise Recursive DNS (Domain Name System) servers, as mandated by the DoDIN service provider Defense Research and Engineering Network (DREN), meets the intent of this requirement. 

Verify that the server is configured to forward all DNS traffic to the DISA Enterprise Recursive Service (ERS) anycast IP addresses ( <IP_ADDRESS_LIST>; ):

Inspect the "named.conf" file for the following:

forward only;
forwarders { <IP_ADDRESS_LIST>; };

If the "named.conf" options are not set to forward queries only to the ERS anycast IPs, this is a finding.

Note: "<IP_ADDRESS_LIST>" should be replaced with the current ERS IP addresses.'
  desc 'fix', 'Configure the BIND 9.x caching name server to utilize the DISA ERS anycast IP addresses.

Edit the "named.conf" file and add the following to the global options statement:

forward only;
forwarders { <IP_ADDRESS_LIST>; };

Note: "<IP_ADDRESS_LIST>" should be replaced with the current ERS IP addresses.

Restart the BIND 9.x process.'
  impact 0.5
  ref 'DPMS Target BIND 9.x'
  tag check_id: 'C-7856r283857_chk'
  tag severity: 'medium'
  tag gid: 'V-207601'
  tag rid: 'SV-207601r612253_rule'
  tag stig_id: 'BIND-9X-001702'
  tag gtitle: 'SRG-APP-000516-DNS-000500'
  tag fix_id: 'F-7856r283858_fix'
  tag 'documentable'
  tag legacy: ['SV-87143', 'V-72519']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
