control 'SV-79737' do
  title 'To protect against data mining, the DataPower Gateway providing content filtering must prevent SQL injection attacks launched against data storage objects, including, at a minimum, databases, database records, and database fields.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to prevent attacks launched against organizational information from unauthorized data mining may result in the compromise of information.

SQL injection attacks are the most prevalent attacks against web applications and databases. These attacks inject SQL commands that can read, modify, or compromise the meaning of the original SQL query. An attacker can spoof identity; expose, tamper, destroy, or make existing data unavailable; or gain unauthorized privileges on the database server.

Compliance requires the ALG to have the capability to prevent SQL code injections. Examples include a Web Application Firewalls (WAFs) or database application gateways.'
  desc 'check', 'Search Bar “Processing Rule” >> Processing rule.

If “Rule Action” does not contain a “Filter” action, this is a finding.'
  desc 'fix', 'Search Bar “Processing Rule” >> processing rule >> Rule Action “+” >> Action Type “Filter”. 

In the filter action, specify that the provided XSL stylesheet, store:///SQL-Injection-Filter.xsl, be used for the transform.

For the injection pattern file, specify store:///SQL-Injection-Patterns.xml, or specify the following name-value pair for the stylesheet parameters:

Name: {http://www.datapower.com/param/config}SQLPatternFile
Value: store:///SQL-Injection-Patterns.xml'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65875r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65247'
  tag rid: 'SV-79737r1_rule'
  tag stig_id: 'WSDP-AG-000077'
  tag gtitle: 'SRG-NET-000318-ALG-000152'
  tag fix_id: 'F-71187r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002346']
  tag nist: ['AC-23']
end
