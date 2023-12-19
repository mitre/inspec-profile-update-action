control 'SV-79499' do
  title 'To protect against unauthorized data mining, the DBN-6300 must detect SQL code injection attacks launched against data storage objects, including, at a minimum, databases, database records, queries, and fields.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks that use unauthorized data mining techniques to attack databases may result in the compromise of information.

Injection attacks allow an attacker to inject code into a program or query or inject malware onto a computer to execute remote commands that can read or modify a database or change data on a website. Web applications frequently access databases to store, retrieve, and update information. An attacker can construct inputs that the database will execute. This is most commonly referred to as a code injection attack. This type of attack includes XPath and LDAP injections. 

IDPS component(s) with anomaly detection must be included in the IDPS implementation to protect against unauthorized data mining. These components must include rules and anomaly detection algorithms to monitor for atypical database queries or accesses.'
  desc 'check', 'Verify that the DBN-6300 is configured to detect code injection attacks. 
 
Navigate to Application >> Time Learning. 
 
Validate that the database or databases of interest has/have the "state" shield set to green (in detection mode). 
 
If the "state" shield is not set to green, this is a finding (as the database or databases are not in detection mode).'
  desc 'fix', 'Configure the DBN-6300 to detect code injection attacks.
 
Navigate to Application >> Time Learning.
 
Validate that the database or databases of interest has the "state" shield set to green (in detection mode).
 
If the "state" shield is not set to green:

1) Create a learned set (or new learned set) by clicking on the caret to the left of the database name;
2) Click on the "+" to the left of the "Time Periods" label;
3) Accept the default time period or enter the desired time period for the Learned Set; and
4) Click on "Commit Learning". This may take a small amount of time and will finish when the "Learned State" shows "Passed" and the "state" shield turns to green. Now the database is in protection mode for SQL injection attack.'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 IDPS'
  tag check_id: 'C-65667r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65009'
  tag rid: 'SV-79499r1_rule'
  tag stig_id: 'DBNW-IP-000035'
  tag gtitle: 'SRG-NET-000319-IDPS-00184'
  tag fix_id: 'F-70949r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002347']
  tag nist: ['AC-23']
end
