control 'SV-86101' do
  title 'The CA API Gateway that provides intermediary services for FTP must inspect inbound and outbound FTP communications traffic for protocol compliance and protocol anomalies.'
  desc 'Application protocol anomaly detection examines application layer protocols such as FTP to identify attacks based on observed deviations in the normal RFC behavior of a protocol or service. This type of monitoring allows for the detection of known and unknown exploits, which exploit weaknesses of commonly used protocols.

Since protocol anomaly analysis examines the application payload for patterns or anomalies, an FTP proxy must be included in the ALG. This ALG will be configured to inspect inbound and outbound FTP communications traffic to detect protocol anomalies such as malformed message and command insertion attacks.

The CA API Gateway must be configured to inspect incoming and outgoing FTP traffic for protocol compliance and anomalies such as limiting message size, protecting against code injection cross-site request forgery, SQL attacks, and XML and JSON document structure validation; validate content; and/or use third-party antivirus scanning. Also, regular expressions can be used to detect any known attack patterns within policies.'
  desc 'check', 'Open the CA API Gateway - Policy Manager and double-click all Registered Services requiring the inspection of FTP traffic for anomalies.

Verify the "Route via FTP(s)" Assertion is included within the policies. 

Also, verify the FTP Listen Port exists and the settings are configured in accordance with organizational requirements by selecting "Tasks" from the main menu, choosing "Manage Listen Ports", and validating that an FTP/FTPS Protocol Listen Port has been added/configured properly including setting the maximum message size property. 

If the "Route via FTP(s)" Assertion is not included in the policies or the Listen port has not been added/configured in accordance with organizational requirements, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager and double-click all Registered Services requiring the inspection of FTP traffic for anomalies that did not include a "Route via FTP(s)" Assertion. 

Add the "Route via FTP(s)" Assertion and configure in accordance with organizational requirements. 

Also, if the FTP Listen Port was not present or configured properly, verify/add the FTP Listen Port by selecting "Tasks" from the main menu, choosing "Manage Listen Ports", and updating/adding the FTP/FTPS Protocol Listen Port in accordance with organizational requirements, including setting the maximum message size property.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71867r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71477'
  tag rid: 'SV-86101r1_rule'
  tag stig_id: 'CAGW-GW-000930'
  tag gtitle: 'SRG-NET-000512-ALG-000065'
  tag fix_id: 'F-77797r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001125']
  tag nist: ['CM-6 b', 'SC-7 (17)']
end
