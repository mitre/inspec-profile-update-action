control 'SV-69655' do
  title 'To protect against unauthorized data mining, the IDPS must detect SQL injection attacks launched against data storage objects, including, at a minimum, databases, database records, and database fields.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks that use unauthorized data mining techniques to attack databases may result in the compromise of information.

SQL injection attacks are the most prevalent attacks against web applications and databases. These attacks inject SQL commands that can read, modify, or compromise the meaning of the original SQL query. An attacker can spoof identity; expose, tamper, destroy, or make existing data unavailable; or gain unauthorized privileges on the database server.

IDPS component(s) with anomaly detection must be included in the IDPS implementation to monitor for and detect unauthorized data mining. These components must include rules and anomaly detection algorithms to monitor for SQL injection attacks.'
  desc 'check', 'Verify the IDPS detects SQL injection attacks launched against data storage objects, including, at a minimum, databases, database records, and database fields.

If the IDPS does not detect SQL injection attacks launched against data storage objects, including, at a minimum, databases, database records, and database fields, this is a finding.'
  desc 'fix', 'Configure the IDPS to detect SQL injection attacks launched against data storage objects, including, at a minimum, databases, database records, and database fields.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-56023r1_chk'
  tag severity: 'medium'
  tag gid: 'V-55409'
  tag rid: 'SV-69655r1_rule'
  tag stig_id: 'SRG-NET-000319-IDPS-00186'
  tag gtitle: 'SRG-NET-000319-IDPS-00186'
  tag fix_id: 'F-60273r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002347']
  tag nist: ['AC-23']
end
