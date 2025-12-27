control 'SV-86047' do
  title 'To protect against data mining, the CA API Gateway providing content filtering must detect SQL injection attacks launched against data storage objects, including, at a minimum, databases, database records, and database fields.'
  desc %q(Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks launched against organizational databases may result in the compromise of information.

SQL injection attacks are the most prevalent attacks against web applications and databases. These attacks inject SQL commands that can read, modify, or compromise the meaning of the original SQL query. An attacker can spoof identity; expose, tamper, destroy, or make existing data unavailable; or gain unauthorized privileges on the database server.

CA API Gateways with anomaly detection must be configured to protect against unauthorized data mining attacks. These devices must include rules and anomaly detection algorithms to monitor for atypical database queries or accesses. Examples include Web Application Firewalls (WAFs) or database application gateways.

The CA API Gateway must include threat protection mechanisms such as a "Protect Against SQL Attack" Assertion configured in accordance with organizational requirements and used in a Registered Service's policy requiring data mining protection to help detect SQL Injection attacks.)
  desc 'check', 'Open the CA API Gateway - Policy Manager. 

Double-click all Registered Services that access a protected database and verify the "Protect Against SQL Attacks" Threat Protection Assertion is included as part of the policies. 

If it is not included, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager. 

Double-click on the Registered Services that do not have the "Protect Against SQL Attacks" Threat Protection Assertion added to their policy and add it from the list of Assertions. 

Chose from the list of available protections for the Assertion to meet the appropriate organizational requirement.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71813r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71423'
  tag rid: 'SV-86047r1_rule'
  tag stig_id: 'CAGW-GW-000570'
  tag gtitle: 'SRG-NET-000319-ALG-000020'
  tag fix_id: 'F-77741r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002347']
  tag nist: ['AC-23']
end
