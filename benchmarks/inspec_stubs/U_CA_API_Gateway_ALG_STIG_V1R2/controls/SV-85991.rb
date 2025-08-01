control 'SV-85991' do
  title 'The CA API Gateway must detect, at a minimum, mobile code that is unsigned or exhibiting unusual behavior, has not undergone a risk assessment, or is prohibited for use based on a risk assessment.'
  desc "Mobile code is defined as software modules obtained from remote systems, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient.

Examples of mobile code include JavaScript, VBScript, Java applets, ActiveX controls, Flash animations, Shockwave videos, and macros embedded within Microsoft Office documents. Mobile code can be exploited to attack a host. It can be sent as an email attachment or embedded in other file formats not traditionally associated with executable code.

While the ALG cannot replace the network IDS or the antivirus and host-based IDS (HIDS) protection installed on the network's endpoints, vendor or locally created sensor rules can be implemented that provide pre-emptive defense against both known and zero-day vulnerabilities. Many of the protections may provide defenses before vulnerabilities are discovered and rules or blacklist updates are distributed by antivirus or malicious code solution vendors.

To monitor for and detect known prohibited mobile code or approved mobile code that violates permitted usage requirements, the ALG must implement policy filters, rules, signatures, and anomaly analysis.

The CA API Gateway must block against code injection and SQL injection attacks, helping to prevent and detect any mobile code that is exhibiting unusual behavior through the injection of incorrect code or wrongly formatted SQL statements within all registered services policies as per organizational requirements."
  desc 'check', 'Open the CA API Gateway - Policy Manager. 

Double-click all Registered Services that require protection from unusual mobile code activity and verify the "Protect Against SQL Attacks" and "Protect Against Code Injection" Threat Protection Assertions are included as part of the policies.

If they are not included, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager. 

Double-click on the Registered Services that did not have the "Protect Against SQL Attacks" and "Protect Against Code Injection" Threat Protection Assertions added to their policies and add them from the list of Assertions. 

Chose from the list of available protections for the Assertions to meet the appropriate organizational requirement for protection against unusual mobile code activity.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71767r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71367'
  tag rid: 'SV-85991r1_rule'
  tag stig_id: 'CAGW-GW-000390'
  tag gtitle: 'SRG-NET-000228-ALG-000108'
  tag fix_id: 'F-77677r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001166']
  tag nist: ['SC-18 (1)']
end
