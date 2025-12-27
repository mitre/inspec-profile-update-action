control 'SV-215740' do
  title 'The BIG-IP Core implementation must be configured to restrict or block harmful or suspicious communications traffic by controlling the flow of information between interconnected networks based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.'
  desc 'Information flow control regulates where information is allowed to travel within a network and between interconnected networks. Blocking or restricting detected harmful or suspicious communications between interconnected networks enforces approved authorizations for controlling the flow of traffic.

This requirement applies the Application Layer Gateway (ALG) when used as a gateway or boundary device that allows traffic flow between interconnected networks of differing security policies.

The ALG is installed and configured in such a way that it restricts or blocks information flows based on guidance in the Ports, Protocols, and Services Management (PPSM) regarding restrictions for boundary crossing for ports, protocols and services. Information flow restrictions may be implemented based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.

The ALG must be configured with policy filters (e.g., security policy, rules, and/or signatures) that restrict or block information system services; provide a packet-filtering capability based on header information; and/or perform message filtering based on message content. The policy filters used depend upon the type of application gateway (e.g., web, email, or TLS).'
  desc 'check', 'If the BIG-IP Core does not perform packet-filtering intermediary services for virtual servers, this is not applicable.

When packet-filtering intermediary services are performed, verify the BIG-IP Core is configured as follows:

Verify Virtual Server(s) in the BIG-IP LTM module is configured with an AFM policy to restrict or block harmful or suspicious communications traffic by controlling the flow of information between interconnected networks based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Navigate to the Security >> Policies tab.

Verify that "Network Firewall" Enforcement is set to "Policy Rules..." and "Policy" is set to use an AFM policy to restrict or block harmful or suspicious communications traffic by controlling the flow of information between interconnected networks based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.

If the BIG-IP Core is not configured to restrict or block harmful or suspicious communications traffic by controlling the flow of information between interconnected networks based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic, this is a finding.'
  desc 'fix', 'If user packet-filtering intermediary services are provided, configure the BIG-IP Core as follows: 

Configure a policy in the BIG-IP AFM module to restrict or block harmful or suspicious communications traffic by controlling the flow of information between interconnected networks based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.

Apply the AFM policy to the applicable Virtual Server(s) in the BIG-IP LTM module to restrict or block harmful or suspicious communications traffic by controlling the flow of information between interconnected networks.'
  impact 0.7
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16932r291033_chk'
  tag severity: 'high'
  tag gid: 'V-215740'
  tag rid: 'SV-215740r557356_rule'
  tag stig_id: 'F5BI-LT-000007'
  tag gtitle: 'SRG-NET-000019-ALG-000018'
  tag fix_id: 'F-16930r291034_fix'
  tag 'documentable'
  tag legacy: ['SV-74691', 'V-60261']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
