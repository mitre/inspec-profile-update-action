control 'SV-104183' do
  title 'Symantec ProxySG must restrict or block harmful or suspicious communications traffic by controlling the flow of information between interconnected networks based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.'
  desc 'Information flow control regulates where information is allowed to travel within a network and between interconnected networks. Blocking or restricting detected harmful or suspicious communications between interconnected networks enforces approved authorizations for controlling the flow of traffic.

This requirement applies to the flow of information between the ALG when used as a gateway or boundary device that allows traffic flow between interconnected networks of differing security policies.

The ALG is installed and configured to restrict or block information flows based on guidance in the PPSM regarding restrictions for boundary crossing for ports, protocols, and services. Information flow restrictions may be implemented based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic.

The ALG must be configured with policy filters (e.g., security policy, rules, and/or signatures) that restrict or block information system services, provide a packet-filtering capability based on header information, and/or perform message-filtering based on message content. The policy filters used depend on the type of application gateway (e.g., web, email, or TLS).'
  desc 'check', %q(Verify that ProxySG inspects web traffic for suspicious or harmful traffic. Verify the destination security policy is configured to filter based on destination, headers, geolocation, protocol characteristics, and other available security objects.

1. Log on to the Web Management Console. 
2. Click Configuration >> Visual Policy Manager. 
3. Click "Launch". While in the Visual Policy Manager, click in to each Web Access and SSL Access Layer.
4. Within each layer above, review each rule and verify that the "Destination" fields are not set to "Any" and that they contain URL categories and/or threat risk levels that should be blocked per the organization's security policy.

If Symantec ProxySG does not restrict or block harmful or suspicious communications traffic by controlling the flow of information between interconnected networks based on attribute- and content-based inspection of the source, destination, headers, and/or content of the communications traffic, this is a finding.)
  desc 'fix', %q(Configure ProxySG to restrict access to suspicious or harmful web traffic. Destination security policy must be configured to filter based on destination, headers, geolocation, protocol characteristics, and other available security objects.

1. Log on to the web Management Console.
2. Click Configuration >> Content Filtering.
3. Under "General," ensure that at least one "Provider" is enabled.
4. Click Configuration >> Visual Policy Manager. 
5. Click "Launch". While in the Visual Policy Manager, click into each Web Access and SSL Access Layer.
6. Within each layer above, right-click the "Destination" fields of each rule, click "set", and specify URL categories and/or threat risk levels that should be blocked per the organization's security policy.
7. Click File >> Install Policy on SG Appliance.)
  impact 0.7
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93415r1_chk'
  tag severity: 'high'
  tag gid: 'V-94229'
  tag rid: 'SV-104183r1_rule'
  tag stig_id: 'SYMP-AG-000070'
  tag gtitle: 'SRG-NET-000019-ALG-000018'
  tag fix_id: 'F-100345r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
