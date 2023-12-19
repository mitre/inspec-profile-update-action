control 'SV-86021' do
  title 'To protect against data mining, the CA API Gateway providing content filtering must prevent code injection attacks launched against application objects including, at a minimum, application URLs and application code.'
  desc %q(Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to prevent attacks launched against organizational information from unauthorized data mining may result in the compromise of information.

Injection attacks allow an attacker to inject code into a program or query or inject malware onto a computer to execute remote commands that can read or modify a database or change data on a website. These attacks include buffer overrun, XML, JavaScript, and HTML injections.
 
Compliance requires the CA API Gateway to have the capability to prevent code injections. Examples include Web Application Firewalls (WAFs) or database application gateways.

The CA API Gateway must include threat protection mechanisms such as "Protect Against SQL Attack" and/or "Protect Against Code Injection" Assertions configured in accordance with organizational requirements and used in a Registered Service's policy requiring protection to help prevent code injection attacks launched against data storage objects.)
  desc 'check', 'Open the CA API Gateway - Policy Manager. 

Double-click all Registered Services that access a protected database and verify the "Protect Against SQL Attacks" and "Protect Against Code Injection" Threat Protection Assertions are included as part of the policies. 

If they are not included, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager. 

Double-click on the Registered Services that do not have the "Protect Against SQL Attacks" and "Protect Against Code Injection" Threat Protection Assertions added to their policies and add them from the list of Assertions. 

Chose from the list of available protections for the Assertions to meet the appropriate organizational requirement.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71797r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71397'
  tag rid: 'SV-86021r1_rule'
  tag stig_id: 'CAGW-GW-000540'
  tag gtitle: 'SRG-NET-000318-ALG-000151'
  tag fix_id: 'F-77715r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002346']
  tag nist: ['AC-23']
end
