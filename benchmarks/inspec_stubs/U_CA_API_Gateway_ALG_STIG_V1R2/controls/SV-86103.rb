control 'SV-86103' do
  title 'The CA API Gateway that provides intermediary services for HTTP must inspect inbound and outbound HTTP traffic for protocol compliance and protocol anomalies.'
  desc 'Application protocol anomaly detection examines application layer protocols such as HTTP to identify attacks based on observed deviations in the normal RFC behavior of a protocol or service. This type of monitoring allows for the detection of known and unknown exploits, which exploit weaknesses of commonly used protocols.

Since protocol anomaly analysis examines the application payload for patterns or anomalies, an HTTP proxy must be included in the ALG. This ALG will be configured to inspect inbound and outbound HTTP communications traffic to detect protocol anomalies such as malformed message and command insertion attacks. 

All inbound and outbound traffic, including HTTPS, must be inspected. However, the intention of this policy is not to mandate HTTPS inspection by the ALG. Typically, HTTPS traffic is inspected either at the source or destination and/or is directed for inspection by organizationally-defined network termination point.

The CA API Gateway must be configured to inspect incoming and outgoing HTTP traffic for protocol compliance and anomalies such as limiting message size, protecting against code injection cross-site request forgery, SQL attacks, and XML and JSON document structure validation; validate content; and/or use third-party anti-virus scanning. Also, regular expressions can be used to detect any known attack patterns within policies.'
  desc 'check', 'Open the CA API Gateway - Policy Manager and double-click all Registered Services requiring the inspection of HTTP traffic for anomalies.

Verify the "Route via HTTP(s)" Assertion is included within the policies. 

Also, verify the HTTP Listen Port exists and the settings are configured in accordance with organizational requirements by selecting "Tasks" from the main menu, choosing "Manage Listen Ports", and validating that an HTTP/HTTPS Protocol Listen Port has been added/configured properly, including setting the maximum message size property. 

If the "Route via HTTP(s):" Assertion is not included in the policies or the Listen Port has not been added/configured in accordance with organizational requirements, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager and double-click all Registered Services requiring the inspection of HTTP traffic for anomalies that did not include a "Route via HTTP(s)" Assertion. 

Add the "Route via HTTP(s)" Assertion and configure in accordance with organizational requirements. 

Also, if the HTTP Listen Port was not present or configured properly, verify/add the HTTP Listen Port by selecting "Tasks" from the main menu choosing "Manage Listen Ports", and updating/adding the HTTP/HTTPS Protocol Listen Port in accordance with organizational requirements, including setting the maximum message size property. 

Additionally, the policy can be updated to add other threat protections, such as the "Protect Against Code Injection" or other Assertions listed in the "Threat Protection" Folder Assertion list. 

For more details, refer to the “CA API Management Documentation Wiki" at https://wiki.ca.com/display/GATEWAY90/CA+API+Gateway+Home.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71869r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71479'
  tag rid: 'SV-86103r1_rule'
  tag stig_id: 'CAGW-GW-000940'
  tag gtitle: 'SRG-NET-000512-ALG-000066'
  tag fix_id: 'F-77799r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001125']
  tag nist: ['CM-6 b', 'SC-7 (17)']
end
