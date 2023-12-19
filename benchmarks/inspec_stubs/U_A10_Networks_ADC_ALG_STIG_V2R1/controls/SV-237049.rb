control 'SV-237049' do
  title 'The A10 Networks ADC must protect against TCP and UDP Denial of Service (DoS) attacks by employing Source-IP based connection-rate limiting.'
  desc 'If the network does not provide safeguards against DoS attacks, network resources will be unavailable to users. Installation of content filtering gateways and application layer firewalls at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume/type.

Detection components that use rate-based behavior analysis can detect attacks when signatures for the attack do not exist or are not installed. These attacks include zero-day attacks which are new attacks for which vendors have not yet developed signatures. Rate-based behavior analysis can detect sophisticated, Distributed DoS (DDoS) attacks by correlating traffic information from multiple network segments or components. This requirement applies to the communications traffic functionality of the device as it pertains to handling communications traffic, rather than to the device itself.

The A10 Networks ADC provides Source-IP based connection-rate limiting to mitigate UDP floods and similar attacks. Source-IP based connection-rate limiting protects the system from excessive connection requests from individual clients. If traffic from a client exceeds the configured threshold, the device should be configured to lock out the client for a specified number of seconds. During the lockout period, all connection requests from the client are dropped. The lockout period ranges from 1-3600 seconds (1 hour); there is no default value.'
  desc 'check', 'Review the device configuration.

The following command displays the device configuration and filters the output on the string "slb conn-rate-limit":
show run | inc slb conn-rate-limit

If Source-IP based connection rate limiting is not configured, this is a finding.

If no lockout period is configured as an action, this is a finding.'
  desc 'fix', 'The following command configures Source-IP based connection rate limiting:
slb conn-rate-limit src-ip [tcp | udp] conn-limit per [100 | 1000] [exceed-action [log] [lock-out lockout-period]]

Note: Thresholds are specific to the expected traffic for the system or enclave.'
  impact 0.7
  ref 'DPMS Target A10 Networks ADC ALG'
  tag check_id: 'C-40268r639592_chk'
  tag severity: 'high'
  tag gid: 'V-237049'
  tag rid: 'SV-237049r639594_rule'
  tag stig_id: 'AADC-AG-000099'
  tag gtitle: 'SRG-NET-000362-ALG-000112'
  tag fix_id: 'F-40231r639593_fix'
  tag 'documentable'
  tag legacy: ['SV-82485', 'V-67995']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
