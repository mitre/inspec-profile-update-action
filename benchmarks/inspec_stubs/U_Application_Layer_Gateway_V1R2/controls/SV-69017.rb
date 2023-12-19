control 'SV-69017' do
  title 'To protect against data mining, the ALG providing content filtering must detect SQL injection attacks launched against data storage objects, including, at a minimum, databases, database records, and database fields.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks launched against organizational databases may result in the compromise of information.

SQL injection attacks are the most prevalent attacks against web applications and databases. These attacks inject SQL commands that can read, modify, or compromise the meaning of the original SQL query. An attacker can spoof identity; expose, tamper, destroy, or make existing data unavailable; or gain unauthorized privileges on the database server.

ALGs with anomaly detection must be configured to protect against unauthorized data mining attacks. These devices must include rules and anomaly detection algorithms to monitor for atypical database queries or accesses. Examples include a Web Application Firewalls (WAFs) or database application gateways.'
  desc 'check', 'If the ALG does not perform content filtering as part of the traffic management functions, this is not applicable.

Verify the ALG detects SQL injection attacks launched against data storage objects, including, at a minimum, databases, database records, and database fields.

If the ALG does not detect SQL injection attacks launched against data storage objects, including, at a minimum, databases, database records, and database fields, this is a finding.'
  desc 'fix', 'If the ALG performs content filtering as part of the traffic management functionality, configure the ALG to detect SQL injection attacks launched against data storage objects, including, at a minimum, databases, database records, and database fields.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55393r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54771'
  tag rid: 'SV-69017r1_rule'
  tag stig_id: 'SRG-NET-000319-ALG-000020'
  tag gtitle: 'SRG-NET-000319-ALG-000020'
  tag fix_id: 'F-59629r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002347']
  tag nist: ['AC-23']
end
