control 'SV-79767' do
  title 'The DataPower Gateway providing content filtering must protect against or limit the effects of known and unknown types of Denial of Service (DoS) attacks by employing pattern recognition pre-processors.'
  desc 'If the network does not provide safeguards against DoS attacks, network resources will be unavailable to users.

Installation of content filtering gateways and application layer firewalls at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks.

Detection components that use pattern recognition pre-processors can detect attacks when signatures for the attack do not exist or are not installed. These attacks include zero-day attacks which are new attacks for which vendors have not yet developed signatures.

This requirement applies to the communications traffic functionality of the ALG as it pertains to handling communications traffic, rather than to the ALG device itself.'
  desc 'check', 'XML DoS
Single message attacks: Jumbo Payload, Recursion, Mega Tags, Coercive parsing, Public key; Multiple message: XML flood, Resource hijack. WebGUI Services >> XML Firewall >> Edit XML Firewall XML, Threat Protection tab.

AAA DoS
Protection against DoS flooding attacks. WebGUI Objects >> XML Processing >> AAA Policy, Main tab.

PKCS #7
Document DoS signature-limit protection. WebGUI Objects >> XML Processing >> Processing Action, select Crypto Binary action type.

Service level monitor (SLM) policy. WebGUI Objects >> Monitoring >> SLM Policy.

If these items are not configured, this is a finding.'
  desc 'fix', 'XML DoS
Single message attacks: Jumbo Payload, Recursion, Mega Tags, Coercive parsing, Public key; Multiple message: XML flood, Resource hijack. WebGUI Services >> XML Firewall >> Edit XML Firewall XML, Threat Protection tab.

AAA DoS
Protection against DoS flooding attacks. WebGUI Objects >> XML Processing >> AAA Policy, Main tab.

PKCS #7
Document DoS signature-limit protection. WebGUI Objects >> XML Processing >> Processing Action, select Crypto Binary action type.

Service level monitor (SLM) policy. WebGUI Objects >> Monitoring >> SLM Policy.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65905r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65277'
  tag rid: 'SV-79767r1_rule'
  tag stig_id: 'WSDP-AG-000102'
  tag gtitle: 'SRG-NET-000362-ALG-000155'
  tag fix_id: 'F-71217r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
