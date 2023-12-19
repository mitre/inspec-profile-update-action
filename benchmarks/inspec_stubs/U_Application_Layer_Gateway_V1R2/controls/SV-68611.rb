control 'SV-68611' do
  title 'To protect against data mining, the ALG providing content filtering must prevent code injection attacks from being launched against data storage objects, including, at a minimum, databases, database records, queries, and fields.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to prevent attacks launched against organizational information from unauthorized data mining may result in the compromise of information.

Injection attacks allow an attacker to inject code into a program or query or inject malware onto a computer to execute remote commands that can read or modify a database, or change data on a website. Web applications frequently access databases to store, retrieve, and update information. An attacker can construct inputs that the database will execute. This is most commonly referred to as a code injection attack. This type of attack includes XPath and LDAP injections.

Compliance requires the ALG to have the capability to prevent code injections. Examples include a Web Application Firewalls (WAFs) or database application gateways.'
  desc 'check', 'If the ALG does not perform content filtering as part of the traffic management functions, this is not applicable.

Verify the ALG prevents code injection attacks from being launched against data storage objects, including, at a minimum, databases, database records, queries, and fields.

If the ALG does not prevent code injection attacks from being launched against data storage objects, including, at a minimum, databases, database records, queries, and fields, this is a finding.'
  desc 'fix', 'If the ALG performs content filtering as part of the traffic management functionality, configure the ALG to prevent code injection attacks from being launched against data storage objects, including, at a minimum, databases, database records, queries, and fields.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-54981r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54365'
  tag rid: 'SV-68611r1_rule'
  tag stig_id: 'SRG-NET-000318-ALG-000014'
  tag gtitle: 'SRG-NET-000318-ALG-000014'
  tag fix_id: 'F-59219r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002346']
  tag nist: ['AC-23']
end
