control 'SV-215777' do
  title 'To protect against data mining, the BIG-IP Core implementation providing content filtering must be configured to detect SQL injection attacks being launched against data storage objects, including, at a minimum, databases, database records, and database fields.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks launched against organizational databases may result in the compromise of information.

SQL injection attacks are the most prevalent attacks against web applications and databases. These attacks inject SQL commands that can read, modify, or compromise the meaning of the original SQL query. An attacker can spoof identity; expose, tamper, destroy, or make existing data unavailable; or gain unauthorized privileges on the database server.

ALGs with anomaly detection must be configured to protect against unauthorized data mining attacks. These devices must include rules and anomaly detection algorithms to monitor for atypical database queries or accesses. Examples include Web Application Firewalls (WAFs) or database application gateways.'
  desc 'check', 'If the BIG-IP Core does not perform content filtering as part of the traffic management functionality for virtual servers, this is not applicable.

When content filtering is performed as part of the traffic management functionality, verify the BIG-IP Core is configured as follows:

Verify Virtual Server(s) in the BIG-IP LTM module are configured with an ASM policy to detect SQL injection attacks being launched against data storage objects, including, at a minimum, databases, database records, and database fields.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Navigate to the Security >> Policies tab.

Verify that "Application Security Policy" is Enabled and "Policy" is set to detect SQL injection attacks being launched against data storage objects, including, at a minimum, databases, database records, and database fields.

If the BIG-IP Core is not configured to detect SQL injection attacks launched against data storage objects, including, at a minimum, databases, database records, and database fields, this is a finding.'
  desc 'fix', 'If the BIG-IP Core performs content filtering as part of the traffic management functionality, configure the BIG-IP Core as follows:

Configure a policy in the BIG-IP ASM module to detect SQL injection attacks being launched against data storage objects, including, at a minimum, databases, database records, and database fields.

Apply ASM policy to the applicable Virtual Server(s) in BIG-IP LTM module to detect SQL injection attacks being launched against data storage objects, including, at a minimum, databases, database records, and database fields.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16969r291144_chk'
  tag severity: 'medium'
  tag gid: 'V-215777'
  tag rid: 'SV-215777r557356_rule'
  tag stig_id: 'F5BI-LT-000165'
  tag gtitle: 'SRG-NET-000319-ALG-000020'
  tag fix_id: 'F-16967r291145_fix'
  tag 'documentable'
  tag legacy: ['SV-74765', 'V-60335']
  tag cci: ['CCI-002347']
  tag nist: ['AC-23']
end
