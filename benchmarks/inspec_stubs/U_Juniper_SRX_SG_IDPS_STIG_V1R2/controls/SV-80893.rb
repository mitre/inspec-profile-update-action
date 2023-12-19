control 'SV-80893' do
  title 'The Juniper Networks SRX Series Gateway IDPS must detect, at a minimum, mobile code that is unsigned or exhibiting unusual behavior, has not undergone a risk assessment, or is prohibited for use based on a risk assessment.'
  desc "Mobile code is defined as software modules obtained from remote systems, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient. Examples of mobile code include JavaScript, VBScript, Java applets, ActiveX controls, Flash animations, Shockwave videos, and macros embedded within Microsoft Office documents. Mobile code can be exploited to attack a host. It can be sent as an email attachment or embedded in other file formats not traditionally associated with executable code. 

While the IDPS cannot replace the anti-virus and host-based IDS (HIDS) protection installed on the network's endpoints, vendor or locally created sensor rules can be implemented, which provide preemptive defense against both known and zero-day vulnerabilities. Many of the protections may provide defenses before vulnerabilities are discovered and rules or blacklist updates are distributed by anti-virus or malicious code solution vendors.

To monitor for and detect known prohibited mobile code or approved mobile code that violates permitted usage requirements, the IDPS must implement policy filters, rules, signatures, and anomaly analysis."
  desc 'check', 'From operational mode, enter the following command to verify that the signature-based attack object was created:

show security idp policies

If signature-based attack objects are not created and used, this is a finding.'
  desc 'fix', 'Specify a name for the attack. Specify common properties for the attack. Specify the attack type and context. Specify the attack direction and the shellcode flag. Set the protocol and its fields. Specify the protocol binding and ports. Specify the direction.

[edit]
edit security idp custom-attack <signature-name>
set severity major
set recommended-action drop-packet
set time-binding scope source count 10
set attack-type signature context packet
set attack-type signature shellcode intel
set attack-type signature protocol ip ttl value 128 match equal
set attack-type signature protocol-binding tcp minimum-port 50 maximum-port 100
set attack-type signature direction any'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG IDPS'
  tag check_id: 'C-67049r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66403'
  tag rid: 'SV-80893r1_rule'
  tag stig_id: 'JUSX-IP-000008'
  tag gtitle: 'SRG-NET-000228-IDPS-00196'
  tag fix_id: 'F-72479r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001166']
  tag nist: ['SC-18 (1)']
end
