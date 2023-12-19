control 'SV-68617' do
  title 'To protect against data mining, the ALG providing content filtering must detect code injection attacks from being launched against data storage objects, including, at a minimum, databases, database records, queries, and fields.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks launched against organizational databases may result in the compromise of information.

Injection attacks allow an attacker to inject code into a program or query or inject malware onto a computer to execute remote commands that can read or modify a database, or change data on a website. Web applications frequently access databases to store, retrieve, and update information. An attacker can construct inputs that the database will execute. This is most commonly referred to as a code injection attack. This type of attack includes XPath and LDAP injections.
 
ALGs with anomaly detection must be configured to protect against unauthorized code injections. These devices must include rules and anomaly detection algorithms to monitor for atypical database queries or accesses. Examples include a Web Application Firewalls (WAFs) or database application gateways.'
  desc 'check', 'If the ALG does not perform content filtering as part of the traffic management functions, this is not applicable.

Verify the ALG detects code injection attacks from being launched against data storage objects, including, at a minimum, databases, database records, queries, and fields.

If the ALG does not detect code injection attacks from being launched against data storage objects, including, at a minimum, databases, database records, queries, and fields, this is a finding.'
  desc 'fix', 'If the ALG performs content filtering as part of the traffic management functionality, configure the ALG to detect code injection attacks from being launched against data storage objects, including, at a minimum, databases, database records, queries, and fields.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-54987r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54371'
  tag rid: 'SV-68617r1_rule'
  tag stig_id: 'SRG-NET-000319-ALG-000015'
  tag gtitle: 'SRG-NET-000319-ALG-000015'
  tag fix_id: 'F-59225r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002347']
  tag nist: ['AC-23']
end
