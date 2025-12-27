control 'SV-80909' do
  title 'The Juniper Networks SRX Series Gateway IDPS must protect against or limit the effects of known and unknown types of Denial of Service (DoS) attacks by employing rate-based attack prevention behavior analysis.'
  desc 'If the network does not provide safeguards against DoS attack, network resources will be unavailable to users.

Installation of IDPS detection and prevention components (i.e., sensors) at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume/type.

Detection components that use rate-based behavior analysis can detect attacks when signatures for the attack do not exist or are not installed. These attacks include zero-day attacks which are new attacks for which vendors have not yet developed signatures. Rate-based behavior analysis can detect sophisticated, Distributed DoS (DDoS) attacks by correlating traffic information from multiple network segments or components.

The Juniper SRX must be configured with screens using the Firewall STIG, but must also be configured for anomaly-based protection using various locally developed anomaly-based attack objects.'
  desc 'check', 'From operational mode, enter the following command to verify that the anomaly-based attack object was created: 

show idp security policies

If anomaly-based attack objects are not created, bound to a zone, and active, this is a finding.'
  desc 'fix', 'Create a protocol anomaly-based attack object:

Specify a name for the attack.
[edit]
security idp custom-attack anomaly1

Specify common properties for the attack.
[edit security idp custom-attack anomaly1]
set severity info
set time-binding scope peer count 2

Specify the attack type and test condition.
[edit] 
security idp custom-attack anomaly1set attack-type anomaly test OPTIONS_UNSUPPORTED

Specify other properties for the anomaly attack.
[edit]
security idp custom-attack anomaly1]
set attack-type anomaly service TCP
u set attack-type anomaly direction any
attack-type anomaly shellcode spark'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG IDPS'
  tag check_id: 'C-67065r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66419'
  tag rid: 'SV-80909r1_rule'
  tag stig_id: 'JUSX-IP-000017'
  tag gtitle: 'SRG-NET-000362-IDPS-00196'
  tag fix_id: 'F-72495r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
