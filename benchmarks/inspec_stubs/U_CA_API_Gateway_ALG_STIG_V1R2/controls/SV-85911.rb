control 'SV-85911' do
  title 'The CA API Gateway must restrict or block harmful or suspicious communications traffic by controlling the flow of information between interconnected networks based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.'
  desc 'Information flow control regulates where information is allowed to travel within a network and between interconnected networks. Blocking or restricting detected harmful or suspicious communications between interconnected networks enforces approved authorizations for controlling the flow of traffic.

This requirement applies to the flow of information between the CA API Gateway when used as a gateway or boundary device that allows traffic flow between interconnected networks of differing security policies.

The CA API Gateway should be installed and configured to restrict or block information flows based on guidance in the Ports, Protocols, and Services Management (PPSM) regarding restrictions for boundary crossing for ports, protocols, and services. Information flow restrictions may be implemented based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.

The CA API Gateway policies securing the Registered Services should include rules to control the flow of information between systems and networks with policy filters (e.g., rules that parse the Request Message attributes and/or signatures) that restrict or block information system services; provide a packet-filtering capability based on header information; and/or perform message filtering based on message content.'
  desc 'check', 'Open the CA API Gateway - Policy Manager. 

Double-click all Registered Services required to restrict or block harmful or suspicious traffic. 

Verify the policies include the proper logic and flow based on the information derived from parsing the attributes of the message request. 

The policy should be configured to do comparisons and provide logical groupings of assertions using the "At least one..." and "All..." assertions so multiple checks can be performed on various attributes to control access to resources.

If it has not, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager.

Double-click all Registered Services required to restrict or block harmful or suspicious traffic. 

Add /update the policy with the appropriate Assertions and include the proper logic and flow based on the information derived from parsing the attributes of a message request to the API in accordance with organizational requirements. 

The policy should be configured to do comparisons and provide logical groupings of assertions using the "At least one..." and "All..." assertions so multiple checks can be performed on various attributes to control access to resources.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71677r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71287'
  tag rid: 'SV-85911r1_rule'
  tag stig_id: 'CAGW-GW-000120'
  tag gtitle: 'SRG-NET-000019-ALG-000018'
  tag fix_id: 'F-77593r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
