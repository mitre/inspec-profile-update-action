control 'SV-80913' do
  title 'The Juniper Networks SRX Series Gateway IDPS must protect against or limit the effects of known types of Denial of Service (DoS) attacks by employing signatures.'
  desc 'If the network does not provide safeguards against DoS attack, network resources will be unavailable to users. 

Installation of IDPS detection and prevention components (i.e., sensors) at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume, type, or protocol usage.

Detection components that use signatures can detect known attacks by using known attack signatures. Signatures are usually obtained from and updated by the IDPS component vendor. These attacks include SYN-flood, ICMP-flood, and Land Attacks.

This requirement applies to the communications traffic functionality of the IDPS as it pertains to handling communications traffic, rather than to the IDPS device itself. The Juniper SRX must be configured with screens using the Firewall STIG to protect against flood and DOS attacks type attacks, but must also be configured for anomaly-based protection'
  desc 'check', 'Verify an attack group or rule is configured.

[edit]
show security idp policies

If an attack group(s) or rules are not implemented to detect flood and DOS attacks, this is a finding.'
  desc 'fix', 'Configure an attack group for "FLOOD" and "DOS" attacks in the signature database which are recommended. Consult the Junos Security Intelligence Center IDP signatures website for a list and details of each attack, along with recommended action upon detection. Then add the attack group to a policy.

Specify the attack group as match criteria in an IDP policy rule.'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG IDPS'
  tag check_id: 'C-67069r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66423'
  tag rid: 'SV-80913r1_rule'
  tag stig_id: 'JUSX-IP-000019'
  tag gtitle: 'SRG-NET-000362-IDPS-00198'
  tag fix_id: 'F-72499r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
