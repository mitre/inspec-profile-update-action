control 'SV-68877' do
  title 'The ALG providing content filtering must protect against or limit the effects of known and unknown types of Denial of Service (DoS) attacks by employing pattern recognition pre-processors.'
  desc 'If the network does not provide safeguards against DoS attacks, network resources will be unavailable to users.

Installation of content filtering gateways and application layer firewalls at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks.

Detection components that use pattern recognition pre-processors can detect attacks when signatures for the attack do not exist or are not installed. These attacks include zero-day attacks which are new attacks for which vendors have not yet developed signatures.

This requirement applies to the communications traffic functionality of the ALG as it pertains to handling communications traffic, rather than to the ALG device itself.'
  desc 'check', 'If the ALG does not perform content filtering as part of the traffic management functions, this is not applicable.

Verify the ALG protects against or limits the effects of known and unknown types of DoS attacks by employing pattern recognition pre-processors.

If the ALG does not protect against or limit the effects of known and unknown types of DoS attacks by employing pattern recognition pre-processors, this is a finding.'
  desc 'fix', 'If the ALG performs content filtering as part of the traffic management functionality, configure the ALG to protect against or limit the effects of known and unknown types of DoS attacks by employing pattern recognition pre-processors.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55251r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54631'
  tag rid: 'SV-68877r1_rule'
  tag stig_id: 'SRG-NET-000362-ALG-000155'
  tag gtitle: 'SRG-NET-000362-ALG-000155'
  tag fix_id: 'F-59487r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
