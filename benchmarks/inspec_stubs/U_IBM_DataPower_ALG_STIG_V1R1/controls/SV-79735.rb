control 'SV-79735' do
  title 'To protect against data mining, the DataPower Gateway providing content filtering must prevent code injection attacks launched against application objects including, at a minimum, application URLs and application code.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to prevent attacks launched against organizational information from unauthorized data mining may result in the compromise of information.

Injection attacks allow an attacker to inject code into a program or query or inject malware onto a computer to execute remote commands that can read or modify a database, or change data on a website. These attacks include buffer overrun, XML, JavaScript, and HTML injections.
 
Compliance requires the ALG to have the capability to prevent code injections. Examples include a Web Application Firewalls (WAFs) or database application gateways.'
  desc 'check', 'Search Bar “Processing Rule” >> Processing rule.

If “Rule Action” does not contain a “Filter” action, this is a finding.'
  desc 'fix', 'Search Bar “Processing Rule” >> processing rule >> Rule Action “+” >> Action Type “Filter”. 

In the filter action, specify that the provided XSL stylesheet, store:///SQL-Injection-Filter.xsl, be used for the transform.

For the injection pattern file, specify store:///SQL-Injection-Patterns.xml, or specify the following name-value pair for the stylesheet parameters:

Name: {http://www.datapower.com/param/config}SQLPatternFile
Value: store:///SQL-Injection-Patterns.xml'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65873r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65245'
  tag rid: 'SV-79735r1_rule'
  tag stig_id: 'WSDP-AG-000076'
  tag gtitle: 'SRG-NET-000318-ALG-000151'
  tag fix_id: 'F-71185r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002346']
  tag nist: ['AC-23']
end
