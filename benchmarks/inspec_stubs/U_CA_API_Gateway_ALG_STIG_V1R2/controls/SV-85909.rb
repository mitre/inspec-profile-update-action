control 'SV-85909' do
  title 'The CA API Gateway must enforce approved authorizations for controlling the flow of information within the network based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.'
  desc "Information flow control regulates where information is allowed to travel within a network. The flow of all network traffic must be monitored and controlled so it does not introduce any unacceptable risk to the network infrastructure or data.

Information flow control policies and enforcement mechanisms are commonly employed by organizations to control the flow of information between designated sources and destinations (e.g., networks, individuals, devices) within information systems. Examples of information flow control restrictions include keeping export-controlled information from being transmitted in the clear to the Internet or blocking information marked as classified but being transported to an unapproved destination.

Using the CA API Gateway - Policy Manager, when creating polices to meet this requirement, the policies should be configured to leverage attributes from the ${request} variable, which contains information about the requesting client's IP address and identity, as well as message headers and body (content) that make up the request.

The CA API Gateway request message headers and content should be parsed and matched against regular expressions (regex) patterns for any text content, XPath expressions for XML content, and JSON path for JSON content relevant to the required flow of information."
  desc 'check', 'Open the CA API Gateway - Policy Manager. 

Double-click all Registered Services requiring enforced authorization for controlling the flow of information. 

Verify the policies include the proper logic and flow based on the information derived from parsing the attributes of the message request. 

The policy should be configured to do comparisons and provide logical groupings of assertions using the "At least one..." and "All..." assertions so multiple checks can be performed on various attributes to control access to resources.

If it has not, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager. 

Double-click all Registered Services requiring enforced authorization for controlling the flow of information. 

Add/update the policy with the appropriate Assertions and include the proper logic and flow based on the information derived from parsing the attributes of a message request to the API in accordance with organizational requirements. 

The policy should be configured to do comparisons and provide logical groupings of assertions using the "At least one..." and "All..." assertions so multiple checks can be performed on various attributes to control access to resources.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71675r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71285'
  tag rid: 'SV-85909r1_rule'
  tag stig_id: 'CAGW-GW-000110'
  tag gtitle: 'SRG-NET-000018-ALG-000017'
  tag fix_id: 'F-77591r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
