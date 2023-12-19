control 'SV-80903' do
  title 'To protect against unauthorized data mining, the Juniper Networks SRX Series Gateway IDPS must detect code injection attacks launched against data storage objects, including, at a minimum, databases, database records, queries, and fields.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks that use unauthorized data mining techniques to attack databases may result in the compromise of information.

Injection attacks allow an attacker to inject code into a program or query or inject malware onto a computer to execute remote commands that can read or modify a database, or change data on a website. Web applications frequently access databases to store, retrieve, and update information. An attacker can construct inputs that the database will execute. This is most commonly referred to as a code injection attack. This type of attack includes XPath and LDAP injections.

IDPS component(s) with anomaly detection must be included in the IDPS implementation to protect against unauthorized data mining. These components must include rules and anomaly detection algorithms to monitor for atypical database queries or accesses.'
  desc 'check', 'Verify an attack group is configured.

[edit]
show security idp policies

If an attack group or rule(s) is not implemented to monitor for code injection attacks that could be launched against data storage objects, this is a finding.'
  desc 'fix', 'Configure an attack group for "INJ" and "CMDEXEC" attacks in the signature database which are recommended. Consult the Junos Security Intelligence Center IDP signatures website for a list and details of each attack, along with recommended action upon detection. Then add the attack group to a policy.

Specify the attack group as match criteria in an IDP policy rule.'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG IDPS'
  tag check_id: 'C-67059r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66413'
  tag rid: 'SV-80903r1_rule'
  tag stig_id: 'JUSX-IP-000014'
  tag gtitle: 'SRG-NET-000319-IDPS-00184'
  tag fix_id: 'F-72489r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002347']
  tag nist: ['AC-23']
end
