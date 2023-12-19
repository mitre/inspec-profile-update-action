control 'SV-69595' do
  title 'The IDPS must protect against or limit the effects of known types of Denial of Service (DoS) attacks by employing signatures.'
  desc 'If the network does not provide safeguards against DoS attack, network resources will be unavailable to users. 

Installation of IDPS detection and prevention components (i.e., sensors) at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume, type, or protocol usage.

Detection components that use signatures can detect known attacks by using known attack signatures. Signatures are usually obtained from and updated by the IDPS component vendor. These attacks include SYN-flood, ICMP-flood, and Land Attacks.

This requirement applies to the communications traffic functionality of the IDPS as it pertains to handling communications traffic, rather than to the IDPS device itself.'
  desc 'check', 'Verify the IDPS protects against or limits the effects of known types of DoS attacks by employing signatures.

If the device does not protect against or limit the effects of known types of DoS attacks by employing signatures, this is a finding.'
  desc 'fix', 'Configure the IDPS to protect against or limit the effects of known types of DoS attacks by employing signatures.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-55971r1_chk'
  tag severity: 'medium'
  tag gid: 'V-55349'
  tag rid: 'SV-69595r1_rule'
  tag stig_id: 'SRG-NET-000362-IDPS-00198'
  tag gtitle: 'SRG-NET-000362-IDPS-00198'
  tag fix_id: 'F-60215r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
