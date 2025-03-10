control 'SV-215790' do
  title 'The BIG-IP Core implementation must be configured to protect against known and unknown types of Denial of Service (DoS) attacks by employing rate-based attack prevention behavior analysis when providing content filtering to virtual servers.'
  desc 'If the network does not provide safeguards against DoS attacks, network resources will be unavailable to users.

Installation of content filtering gateways and application layer firewalls at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume/type.

Detection components that use rate-based behavior analysis can detect attacks when signatures for the attack do not exist or are not installed. These attacks include zero-day attacks, which are new attacks for which vendors have not yet developed signatures. Rate-based behavior analysis can detect sophisticated, Distributed DoS (DDoS) attacks by correlating traffic information from multiple network segments or components.

This requirement applies to the functionality of the ALG as it pertains to handling communications traffic rather than to the ALG device itself.'
  desc 'check', 'If the BIG-IP Core does not perform content filtering as part of the traffic management functionality for virtual servers, this is not applicable.

When content filtering is performed as part of the traffic management functionality, verify the BIG-IP Core is configured as follows:

Verify Virtual Server(s) in the BIG-IP LTM module are configured with a security policy to protect against or limit the effects of known and unknown types of DoS attacks by employing rate-based attack prevention behavior analysis.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Navigate to the Security >> Policies tab.

Verify that "DoS Protection Profile" is Enabled and "Profile" is set to use locally configured DoS protection Profile.

Verify the DoS protection profile that is set for the Virtual Server is set to employ rate-based attack prevention:

Navigate to the BIG-IP System manager >> Security >> DoS Protection >> DoS Profiles.

Select the DoS Protection Profile set for the Virtual Server.

Verify that "Application Security" is Enabled under "General Configuration".

Verify that the following are selected for "Prevention Policy" under TPS-base Anomaly in accordance with the organization requirements:

"Source IP-Based Client Side Integrity Defense"
"URL-Based Client Side Integrity Defense"
"Site-wide" Client-Side Integrity Defense"
"Source IP-Base Rate Limiting"
"URL-Based Rate Limiting"
"Site-wide Rate Limiting"

Verify the Criteria for each of the selected Prevention Policies is set in accordance with organization requirements.

If the BIG-IP Core is not configured to protect against or limit the effects of known and unknown types of DoS attacks by employing rate-based attack prevention behavior analysis, this is a finding.'
  desc 'fix', 'If the BIG-IP Core performs content filtering as part of the traffic management functionality, configure the BIG-IP Core to protect against or limit the effects of known and unknown types of DoS attacks by employing rate-based attack prevention behavior analysis.'
  impact 0.7
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16982r291183_chk'
  tag severity: 'high'
  tag gid: 'V-215790'
  tag rid: 'SV-215790r557356_rule'
  tag stig_id: 'F5BI-LT-000215'
  tag gtitle: 'SRG-NET-000362-ALG-000112'
  tag fix_id: 'F-16980r291184_fix'
  tag 'documentable'
  tag legacy: ['SV-74791', 'V-60361']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
