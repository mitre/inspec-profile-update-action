control 'SV-69643' do
  title 'To protect against unauthorized data mining, the IDPS must prevent code injection attacks launched against data storage objects, including, at a minimum, databases, database records, queries, and fields.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks that use unauthorized data mining techniques to attack databases may result in the compromise of information.

Injection attacks allow an attacker to inject code into a program or query or inject malware onto a computer to execute remote commands that can read or modify a database, or change data on a website. Web applications frequently access databases to store, retrieve, and update information. An attacker can construct inputs that the database will execute. This is most commonly referred to as a code injection attack. This type of attack includes XPath and LDAP injections. 

IDPS component(s) with the capability to prevent code injections must be included in the IDPS implementation to protect against unauthorized data mining. These components must include rules and anomaly detection algorithms to monitor for atypical database queries or accesses.'
  desc 'check', 'Verify the IDPS prevents code injection attacks launched against data storage objects, including, at a minimum, databases, database records, queries, and fields.

If the IDPS does not prevent code injection attacks launched against data storage objects, including, at a minimum, databases, database records, queries, and fields, this is a finding.'
  desc 'fix', 'Configure the IDPS components to prevent code injection attacks launched against data storage objects, including, at a minimum, databases, database records, queries, and fields.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-56013r1_chk'
  tag severity: 'medium'
  tag gid: 'V-55397'
  tag rid: 'SV-69643r1_rule'
  tag stig_id: 'SRG-NET-000318-IDPS-00068'
  tag gtitle: 'SRG-NET-000318-IDPS-00068'
  tag fix_id: 'F-60263r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002346']
  tag nist: ['AC-23']
end
