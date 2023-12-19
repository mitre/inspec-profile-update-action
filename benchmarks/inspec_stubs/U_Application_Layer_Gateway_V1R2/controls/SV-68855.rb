control 'SV-68855' do
  title 'The ALG must detect, at a minimum, mobile code that is unsigned or exhibiting unusual behavior, has not undergone a risk assessment, or is prohibited for use based on a risk assessment.'
  desc "Mobile code is defined as software modules obtained from remote systems, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient.

Examples of mobile code include JavaScript, VBScript, Java applets, ActiveX controls, Flash animations, Shockwave videos, and macros embedded within Microsoft Office documents. Mobile code can be exploited to attack a host. It can be sent as an email attachment or embedded in other file formats not traditionally associated with executable code.

While the ALG cannot replace the network IDS or the anti-virus and host-based IDS (HIDS) protection installed on the network's endpoints, vendor or locally created sensor rules can be implemented, which provide preemptive defense against both known and zero-day vulnerabilities. Many of the protections may provide defenses before vulnerabilities are discovered and rules or blacklist updates are distributed by anti-virus or malicious code solution vendors.

To monitor for and detect known prohibited mobile code or approved mobile code that violates permitted usage requirements, the ALG must implement policy filters, rules, signatures, and anomaly analysis."
  desc 'check', 'Verify the ALG detects, at a minimum, mobile code that is unsigned or exhibiting unusual behavior, has not undergone a risk assessment, or is prohibited for use based on a risk assessment.

If the ALG does not detect, at a minimum, mobile code that is unsigned or exhibiting unusual behavior, has not undergone a risk assessment, or is prohibited for use based on a risk assessment, this is a finding.'
  desc 'fix', 'Configure the ALG to detect, at a minimum, mobile code that is unsigned or exhibiting unusual behavior, has not undergone a risk assessment, or is prohibited for use based on a risk assessment.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55229r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54609'
  tag rid: 'SV-68855r1_rule'
  tag stig_id: 'SRG-NET-000228-ALG-000108'
  tag gtitle: 'SRG-NET-000228-ALG-000108'
  tag fix_id: 'F-59465r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001166']
  tag nist: ['SC-18 (1)']
end
