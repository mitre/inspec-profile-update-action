control 'SV-80907' do
  title 'To protect against unauthorized data mining, the Juniper Networks SRX Series Gateway IDPS must detect SQL injection attacks launched against data storage objects, including, at a minimum, databases, database records, and database fields.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks that use unauthorized data mining techniques to attack databases may result in the compromise of information.

SQL injection attacks are the most prevalent attacks against web applications and databases. These attacks inject SQL commands that can read, modify, or compromise the meaning of the original SQL query. An attacker can spoof identity; expose, tamper, destroy, or make existing data unavailable; or gain unauthorized privileges on the database server.

IDPS component(s) with anomaly detection must be included in the IDPS implementation to monitor for and detect unauthorized data mining. These components must include rules and anomaly detection algorithms to monitor for SQL injection attacks.'
  desc 'check', 'Verify an attack group or rule is configured.

[edit]
show security idp policies

If an attack group or rule(s) is not implemented to monitor for SQL injection attacks that could be launched against data storage objects, this is a finding.'
  desc 'fix', 'Configure an attack group for "SQL" attacks in the signature database which are recommended. Consult the Junos Security Intelligence Center IDP signatures website for a list and details of each attack, along with recommended action upon detection. Then add the attack group to a policy.

Specify the attack group as match criteria in an IDP policy rule.'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG IDPS'
  tag check_id: 'C-67063r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66417'
  tag rid: 'SV-80907r1_rule'
  tag stig_id: 'JUSX-IP-000016'
  tag gtitle: 'SRG-NET-000319-IDPS-00186'
  tag fix_id: 'F-72493r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002347']
  tag nist: ['AC-23']
end
