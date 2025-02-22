control 'SV-79743' do
  title 'To protect against data mining, the DataPower Gateway providing content filtering as part of its intermediary services must detect code injection attacks launched against application objects including, at a minimum, application URLs and application code.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks launched against organizational applications may result in the compromise of information.

Injection attacks allow an attacker to inject code into a program or query or inject malware onto a computer to execute remote commands that can read or modify a database, or change data on a website. These attacks include buffer overrun, XML, JavaScript, and HTML injections.

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
  tag check_id: 'C-65881r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65253'
  tag rid: 'SV-79743r1_rule'
  tag stig_id: 'WSDP-AG-000080'
  tag gtitle: 'SRG-NET-000319-ALG-000153'
  tag fix_id: 'F-71193r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002347']
  tag nist: ['AC-23']
end
