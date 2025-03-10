control 'SV-215793' do
  title 'The BIG-IP Core implementation must be configured to protect against or limit the effects of known and unknown types of Denial of Service (DoS) attacks by employing pattern recognition pre-processors when providing content filtering to virtual servers.'
  desc 'If the network does not provide safeguards against DoS attacks, network resources will be unavailable to users.

Installation of content filtering gateways and application layer firewalls at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks.

Detection components that use pattern recognition pre-processors can detect attacks when signatures for the attack do not exist or are not installed. These attacks include zero-day attacks, which are new attacks for which vendors have not yet developed signatures.

This requirement applies to the communications traffic functionality of the ALG as it pertains to handling communications traffic, rather than to the ALG device itself.'
  desc 'check', 'If the BIG-IP Core does not perform content filtering as part of the traffic management functionality for virtual servers, this is not applicable.

When content filtering is performed as part of the traffic management functionality, verify the BIG-IP Core protects against or limits the effects of known and unknown types of DoS attacks by employing pattern recognition pre-processors.

Verify the BIG-IP Core is configured as follows:

Verify Virtual Server(s) in the BIG-IP LTM module are configured with an ASM policy to protect against or limit the effects of known and unknown types of Denial of Service (DoS) attacks by employing pattern recognition pre-processors when providing content filtering to virtual servers.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Navigate to the Security >> Policies tab.

Verify that "DoS Protection Profile" is Enabled and "Profile" is set to use a locally configured DoS protection Profile.

Verify the DoS protection profile that is set for the Virtual Server is set to employ pattern recognition pre-processors:

Navigate to the BIG-IP System manager >> Security >> DoS Protection >> DoS Profiles.

Select the DoS Protection Profile set for the Virtual Server.

Verify that "Application Security" is Enabled under "General Configuration".

Verify that the following are selected for "Prevention Policy" under TPS-base Anomaly in accordance with the organization requirements:

"Source IP-Based Client Side Integrity Defense"
"URL-Based Client Side Integrity Defense"
"Site-wide" Client-Side Integrity Defense"

Verify the Criteria for each of the selected Prevention Policies is set in accordance with organization requirements.

If the BIG-IP Core is not configured to protect against or limit the effects of known and unknown types of DoS attacks by employing pattern recognition pre-processors, this is a finding.'
  desc 'fix', 'If the BIG-IP Core performs content filtering as part of the traffic management functionality, configure the BIG-IP Core as follows:

Configure a policy in the BIG-IP ASM module to protect against or limit the effects of known and unknown types of DoS attacks by employing pattern recognition pre-processors. 

Apply ASM policy to the applicable Virtual Server(s) in the BIG-IP LTM module to protect against or limit the effects of known and unknown types of DoS attacks by employing pattern recognition pre-processors when providing content filtering to virtual servers.'
  impact 0.7
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16985r291192_chk'
  tag severity: 'high'
  tag gid: 'V-215793'
  tag rid: 'SV-215793r831476_rule'
  tag stig_id: 'F5BI-LT-000221'
  tag gtitle: 'SRG-NET-000362-ALG-000155'
  tag fix_id: 'F-16983r291193_fix'
  tag 'documentable'
  tag legacy: ['V-60367', 'SV-74797']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
