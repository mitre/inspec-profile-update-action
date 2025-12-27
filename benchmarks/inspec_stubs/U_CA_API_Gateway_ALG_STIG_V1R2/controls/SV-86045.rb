control 'SV-86045' do
  title 'To protect against data mining, the CA API Gateway providing content filtering must detect code injection attacks from being launched against data storage objects, including, at a minimum, databases, database records, queries, and fields.'
  desc %q(Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks launched against organizational databases may result in the compromise of information.

Injection attacks allow an attacker to inject code into a program or query or inject malware onto a computer to execute remote commands that can read or modify a database or change data on a website. Web applications frequently access databases to store, retrieve, and update information. An attacker can construct inputs that the database will execute. This is most commonly referred to as a code injection attack. This type of attack includes XPath and LDAP injections.
 
CA API Gateways with anomaly detection must be configured to protect against unauthorized code injections. These devices must include rules and anomaly detection algorithms to monitor for atypical database queries or accesses. Examples include Web Application Firewalls (WAFs) or database application gateways. 

The CA API Gateway must include threat protection mechanisms such as a "Protect Against Code Injection" Assertion configured in accordance with organizational requirements and used in a Registered Service's policy requiring data mining protection to help detect code injection attacks.)
  desc 'check', 'Open the CA API Gateway - Policy Manager. 

Double-click all Registered Services that access a protected database and verify the "Protect Against Code Injection Attacks" Threat Protection Assertion is included as part of the policies. 

If it is not included, this is a finding.'
  desc 'fix', 'Open the CA API GW - Policy Manager. 

Double-click on the Registered Services that do not have the "Protect Against SQL Attacks" and "Protect Against Code Injection" Threat Protection Assertions added to their policies and add them from the list of Assertions. Chose from the list of available protections for the Assertions to meet the appropriate organizational requirement.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71811r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71421'
  tag rid: 'SV-86045r1_rule'
  tag stig_id: 'CAGW-GW-000560'
  tag gtitle: 'SRG-NET-000319-ALG-000015'
  tag fix_id: 'F-77739r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002347']
  tag nist: ['AC-23']
end
