control 'SV-215803' do
  title 'The BIG-IP Core implementation must be configured to inspect for protocol compliance and protocol anomalies in inbound HTTP and HTTPS traffic to virtual servers.'
  desc 'Application protocol anomaly detection examines application layer protocols such as HTTP to identify attacks based on observed deviations in the normal RFC behavior of a protocol or service. This type of monitoring allows for the detection of known and unknown exploits that exploit weaknesses of commonly used protocols.

Since protocol anomaly analysis examines the application payload for patterns or anomalies, an HTTP proxy must be included in the ALG. This ALG will be configured to inspect inbound HTTP and HTTPS communications traffic to detect protocol anomalies such as malformed message and command insertion attacks. Note that if mutual authentication is enabled, there will be no way to inspect HTTPS traffic with MITM.'
  desc 'check', 'If the BIG-IP Core does not provide intermediary/proxy services for HTTP and HTTPS communications traffic for virtual servers, this is not applicable.

When intermediary/proxy services for HTTP and HTTPS communications traffic are provided, verify the BIG-IP Core is configured as follows:

Verify the BIG-IP LTM module is configured to inspect for protocol compliance and protocol anomalies in inbound HTTP and HTTPS communications traffic.

Navigate to the BIG-IP System manager >> Security >> Protocol Security >> Security Profiles >> HTTP.

Verify there is at least one profile for managing HTTP traffic.

Select a Profile from the list to verify.

Review each of the following tabs to verify the proper criteria are selected and are set to "Alarm" at a minimum:

"HTTP Protocol Checks"
"Request Checks"
"Blocking Page"

If the BIG-IP Core does not inspect inbound HTTP and HTTPS communications traffic for protocol compliance and protocol anomalies, this is a finding.'
  desc 'fix', 'If the BIG-IP Core provides intermediary/proxy services for HTTP and HTTPS communications traffic, configure the BIG-IP Core to inspect inbound HTTP and HTTPS communications traffic for protocol compliance and protocol anomalies.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16995r291222_chk'
  tag severity: 'medium'
  tag gid: 'V-215803'
  tag rid: 'SV-215803r557356_rule'
  tag stig_id: 'F5BI-LT-000307'
  tag gtitle: 'SRG-NET-000512-ALG-000066'
  tag fix_id: 'F-16993r291223_fix'
  tag 'documentable'
  tag legacy: ['SV-74817', 'V-60387']
  tag cci: ['CCI-000366', 'CCI-001125']
  tag nist: ['CM-6 b', 'SC-7 (17)']
end
