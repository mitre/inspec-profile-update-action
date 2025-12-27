control 'SV-237062' do
  title 'The A10 Networks ADC must protect against ICMP-based Denial of Service (DoS) attacks by employing ICMP Rate Limiting.'
  desc 'If the network does not provide safeguards against DoS attacks, network resources will be unavailable to users. Installation of content filtering gateways and application layer firewalls at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume/type.

Detection components that use rate-based behavior analysis can detect attacks when signatures for the attack do not exist or are not installed. These attacks include zero-day attacks which are new attacks for which vendors have not yet developed signatures. Rate-based behavior analysis can detect sophisticated, Distributed DoS (DDoS) attacks by correlating traffic information from multiple network segments or components. 

The A10 Networks ADC provides an ICMP Rate Limiting feature that monitors the rate of ICMP traffic and drops ICMP packets when the configured thresholds (the normal rate) are exceeded.'
  desc 'check', 'Review the device configuration.

The following command displays the device configuration and filters the output on the string "icmp-rate-limit":
show run | inc icmp-rate-limit

If ICMP rate limiting is not configured, this is a finding.

If no lockout period and maximum rates are configured as an action, this is a finding.'
  desc 'fix', 'The following command configures ICMP rate limiting:
icmp-rate-limit [normal-rate] lockup [max-rate] [lockup-time]'
  impact 0.7
  ref 'DPMS Target A10 Networks ADC ALG'
  tag check_id: 'C-40281r639631_chk'
  tag severity: 'high'
  tag gid: 'V-237062'
  tag rid: 'SV-237062r639633_rule'
  tag stig_id: 'AADC-AG-000155'
  tag gtitle: 'SRG-NET-000362-ALG-000112'
  tag fix_id: 'F-40244r639632_fix'
  tag 'documentable'
  tag legacy: ['SV-82515', 'V-68025']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
