control 'SV-69649' do
  title 'To protect against unauthorized data mining, the IDPS must detect code injection attacks launched against data storage objects, including, at a minimum, databases, database records, queries, and fields.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks that use unauthorized data mining techniques to attack databases may result in the compromise of information.

Injection attacks allow an attacker to inject code into a program or query or inject malware onto a computer to execute remote commands that can read or modify a database, or change data on a website. Web applications frequently access databases to store, retrieve, and update information. An attacker can construct inputs that the database will execute. This is most commonly referred to as a code injection attack. This type of attack includes XPath and LDAP injections.

IDPS component(s) with anomaly detection must be included in the IDPS implementation to protect against unauthorized data mining. These components must include rules and anomaly detection algorithms to monitor for atypical database queries or accesses.'
  desc 'check', 'Verify the IDPS detects code injection attacks launched against data storage objects, including, at a minimum, databases, database records, queries, and fields.

If the IDPS does not detect code injection attacks launched against data storage objects, including, at a minimum, databases, database records, queries, and fields, this is a finding.'
  desc 'fix', 'Configure the IDPS components to detect code injection attacks launched against data storage objects, including, at a minimum, databases, database records, queries, and fields.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-56019r1_chk'
  tag severity: 'medium'
  tag gid: 'V-55403'
  tag rid: 'SV-69649r1_rule'
  tag stig_id: 'SRG-NET-000319-IDPS-00184'
  tag gtitle: 'SRG-NET-000319-IDPS-00184'
  tag fix_id: 'F-60269r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002347']
  tag nist: ['AC-23']
end
