control 'SV-68879' do
  title 'The ALG providing content filtering must protect against known types of Denial of Service (DoS) attacks by employing signatures.'
  desc 'If the network does not provide safeguards against DoS attacks, network resources will be unavailable to users. 

Installation of content filtering gateways and application layer firewalls at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume, type, or protocol usage.

Detection components that use signatures can detect known attacks by using known attack signatures. Signatures are usually obtained from and updated by the ALG component vendor.
 
This requirement applies to the communications traffic functionality of the ALG as it pertains to handling communications traffic, rather than to the ALG device itself.'
  desc 'check', 'If the ALG does not perform content filtering as part of the traffic management functions, this is not applicable.

Verify the ALG protects against or limits the effects of known types of DoS attacks by employing signatures.

If the ALG does not protect against or limit the effects of known types of DoS attacks by employing signatures, this is a finding.'
  desc 'fix', 'If the ALG performs content filtering as part of the traffic management functionality, configure the ALG to protect against or limit the effects of known types of DoS attacks by employing signatures.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55253r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54633'
  tag rid: 'SV-68879r1_rule'
  tag stig_id: 'SRG-NET-000362-ALG-000126'
  tag gtitle: 'SRG-NET-000362-ALG-000126'
  tag fix_id: 'F-59489r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
