control 'SV-74351' do
  title 'The BIG-IP AFM module must be configured to restrict or block harmful or suspicious communications traffic by controlling the flow of information between interconnected networks based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.'
  desc 'Information flow control regulates where information is allowed to travel within a network and between interconnected networks. Blocking or restricting detected harmful or suspicious communications between interconnected networks enforces approved authorizations for controlling the flow of traffic.

This requirement applies to the flow of information between the Application Layer Gateway (ALG) when used as a gateway or boundary device which allows traffic flow between interconnected networks of differing security policies.

The ALG installed and configured in such a way that restricts or blocks information flows based on guidance in the Ports, Protocols, & Services (PPSM) regarding restrictions for boundary crossing for ports, protocols, and services. Information flow restrictions may be implemented based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.

The ALGs must be configured with policy filters (e.g., security policy, rules, and/or signatures) that restrict or block information system services; provide a packet filtering capability based on header information; and/or perform message filtering based on message content. The policy filters used depend upon the type of application gateway (e.g., web, email, or TLS).'
  desc 'check', 'If the BIG-IP AFM module is not used to support user access control intermediary services for virtual servers, this is not applicable.

Verify the BIG-IP AFM module is configured to restrict or block harmful or suspicious communications traffic by controlling the flow of information between interconnected networks based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.

Navigate to the BIG-IP System manager >> Security >> Network Firewall >> Active Rules.

Verify an active rule is configured to restrict or block harmful or suspicious communications traffic by controlling the flow of information between interconnected networks based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.

If the BIG-IP AFM module is not configured to restrict or block harmful or suspicious communications traffic by controlling the flow of information between interconnected networks based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic, this is a finding.'
  desc 'fix', 'If the BIG-IP AFM module is used to support user access control intermediary services for virtual servers, configure the BIG-IP AFM module to restrict or block harmful or suspicious communications traffic by controlling the flow of information between interconnected networks based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.'
  impact 0.7
  ref 'DPMS Target F5 BIG-IP AFM 11.x'
  tag check_id: 'C-60609r2_chk'
  tag severity: 'high'
  tag gid: 'V-59921'
  tag rid: 'SV-74351r1_rule'
  tag stig_id: 'F5BI-AF-000007'
  tag gtitle: 'SRG-NET-000019-ALG-000018'
  tag fix_id: 'F-65329r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
