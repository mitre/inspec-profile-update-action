control 'SV-215792' do
  title 'The BIG-IP Core implementation must be configured to protect against known types of Denial of Service (DoS) attacks by employing signatures when providing content filtering to virtual servers.'
  desc 'If the network does not provide safeguards against DoS attacks, network resources will be unavailable to users. 

Installation of content filtering gateways and application layer firewalls at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume, type, or protocol usage.

Detection components that use signatures can detect known attacks by using known attack signatures. Signatures are usually obtained from and updated by the ALG component vendor.

This requirement applies to the communications traffic functionality of the ALG as it pertains to handling communications traffic rather than to the ALG device itself.'
  desc 'check', 'If the BIG-IP Core does not perform content filtering as part of the traffic management functionality for virtual servers, this is not applicable.

When content filtering is performed as part of the traffic management functionality, verify the BIG-IP Core is configured to protect against known types of DoS attacks by employing signatures.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Navigate to the Security >> Policies tab.

Verify that "DoS Protection Profile" is Enabled and "Profile" is set to use locally configured DoS protection Profile.

If the BIG-IP Core does not protect against known types of DoS attacks by employing signatures, this is a finding.'
  desc 'fix', 'If the BIG-IP Core performs content filtering as part of the traffic management functionality, configure the BIG-IP Core to protect against or limit the effects of known types of DoS attacks by employing signatures.'
  impact 0.7
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16984r291189_chk'
  tag severity: 'high'
  tag gid: 'V-215792'
  tag rid: 'SV-215792r557356_rule'
  tag stig_id: 'F5BI-LT-000219'
  tag gtitle: 'SRG-NET-000362-ALG-000126'
  tag fix_id: 'F-16982r291190_fix'
  tag 'documentable'
  tag legacy: ['V-60365', 'SV-74795']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
