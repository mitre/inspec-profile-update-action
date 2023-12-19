control 'SV-79739' do
  title 'To protect against data mining, the DataPower Gateway providing content filtering must detect code injection attacks from being launched against data storage objects, including, at a minimum, databases, database records, queries, and fields.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks launched against organizational databases may result in the compromise of information.

Injection attacks allow an attacker to inject code into a program or query or inject malware onto a computer to execute remote commands that can read or modify a database, or change data on a website. Web applications frequently access databases to store, retrieve, and update information. An attacker can construct inputs that the database will execute. This is most commonly referred to as a code injection attack. This type of attack includes XPath and LDAP injections.
 
ALGs with anomaly detection must be configured to protect against unauthorized code injections. These devices must include rules and anomaly detection algorithms to monitor for atypical database queries or accesses. Examples include a Web Application Firewalls (WAFs) or database application gateways.'
  desc 'check', 'Search Bar “Processing Rule” >> Processing rule.

If “Rule Action” does not contain a “Filter” action, this is a finding.'
  desc 'fix', 'Search Bar “Processing Rule” >> processing rule >> Rule Action “+” >> Action Type “Filter”. 

In the filter action, specify that the provided XSL stylesheet, store:///SQL-Injection-Filter.xsl, be used for the transform.

For the injection pattern file, specify store:///SQL-Injection-Patterns.xml, or specify the following name-value pair for the stylesheet parameters:

Name: {http://www.datapower.com/param/config}SQLPatternFile
Value: store:///SQL-Injection-Patterns.xml'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65877r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65249'
  tag rid: 'SV-79739r1_rule'
  tag stig_id: 'WSDP-AG-000078'
  tag gtitle: 'SRG-NET-000319-ALG-000015'
  tag fix_id: 'F-71189r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002347']
  tag nist: ['AC-23']
end
