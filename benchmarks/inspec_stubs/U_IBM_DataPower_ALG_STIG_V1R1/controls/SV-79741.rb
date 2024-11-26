control 'SV-79741' do
  title 'To protect against data mining, the DataPower Gateway providing content filtering must detect SQL injection attacks launched against data storage objects, including, at a minimum, databases, database records, and database fields.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks launched against organizational databases may result in the compromise of information.

SQL injection attacks are the most prevalent attacks against web applications and databases. These attacks inject SQL commands that can read, modify, or compromise the meaning of the original SQL query. An attacker can spoof identity; expose, tamper, destroy, or make existing data unavailable; or gain unauthorized privileges on the database server.

ALGs with anomaly detection must be configured to protect against unauthorized data mining attacks. These devices must include rules and anomaly detection algorithms to monitor for atypical database queries or accesses. Examples include a Web Application Firewalls (WAFs) or database application gateways.'
  desc 'check', 'Search Bar “Processing Rule” >> Processing rule.

If “Rule Action” does not contain a “Filter” action, this is a finding.'
  desc 'fix', 'Search Bar “Processing Rule” >> processing rule >> Rule Action “+” >> Action Type “Filter”. 

In the filter action, specify that the provided XSL stylesheet, store:///SQL-Injection-Filter.xsl, be used for the transform.

For the injection pattern file, specify store:///SQL-Injection-Patterns.xml, or specify the following name-value pair for the stylesheet parameters:

Name: {http://www.datapower.com/param/config}SQLPatternFile
Value: store:///SQL-Injection-Patterns.xml'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65879r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65251'
  tag rid: 'SV-79741r1_rule'
  tag stig_id: 'WSDP-AG-000079'
  tag gtitle: 'SRG-NET-000319-ALG-000020'
  tag fix_id: 'F-71191r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002347']
  tag nist: ['AC-23']
end
