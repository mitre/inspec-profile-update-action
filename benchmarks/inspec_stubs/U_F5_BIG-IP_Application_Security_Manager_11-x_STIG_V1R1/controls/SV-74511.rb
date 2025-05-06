control 'SV-74511' do
  title 'To protect against data mining, The BIG-IP ASM module must be configured to detect code injection attacks from being launched against data storage objects, including, at a minimum, databases, database records, queries, and fields when providing content filtering to virtual servers.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks launched against organizational databases may result in the compromise of information.

Injection attacks allow an attacker to inject code into a program or query or inject malware into a computer to execute remote commands that can read or modify a database or change data on a website. Web applications frequently access databases to store, retrieve, and update information. An attacker can construct inputs that the database will execute. This is most commonly referred to as a code injection attack. This type of attack includes XPath and LDAP injections.

ALGs with anomaly detection must be configured to protect against unauthorized code injections. These devices must include rules and anomaly detection algorithms to monitor for atypical database queries or accesses. Examples include Web Application Firewalls (WAFs) or database application gateways.'
  desc 'check', 'If the BIG-IP ASM module is not used to support content filtering as part of the traffic management functions of the BIG-IP Core, this is not applicable.

Verify the BIG-IP ASM module is configured to detect code injection attacks launched against data storage objects, including, at a minimum, databases, database records, queries, and fields.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify the configuration of an ASM policy to prevent code injection attacks.

Navigate to the Security >> Policies tab.

Set "Policy Settings" to "Advanced".

Verify that "Application Security Policy" is Enabled and "Policy" is set to use an ASM policy for the virtual server.

Navigate to the BIG-IP System manager >> Security >> Application Security >> Security Policies.

Select the Security Policy that has been assigned to the Virtual Server(s).

Verify the "Enforcement Mode" is Transparent or Blocking.

Click "Attack Signatures Configurations" for "Signature Staging" under the "Configuration" section.

Review the list under "Assigned Signature Sets" for the following signatures:

Generic Detection Signatures

Custom Systems Signature Set (based on systems identified in the application make-up).

Verify the "Assignment Signature Sets" listed above have the "Alarm" button checked.

If the BIG-IP ASM module is not configured to detect code injection attacks launched against data storage objects, including, at a minimum, databases, database records, queries, and fields, this is a finding.'
  desc 'fix', 'If the BIG-IP ASM module is used to support content filtering as part of the traffic management functionality of the BIG-IP Core, configure the BIG-IP ASM module to detect code injection attacks launched against data storage objects, including, at a minimum, databases, database records, queries, and fields.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP ASM 11.x'
  tag check_id: 'C-60843r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60081'
  tag rid: 'SV-74511r1_rule'
  tag stig_id: 'F5BI-AS-000163'
  tag gtitle: 'SRG-NET-000319-ALG-000015'
  tag fix_id: 'F-65575r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002347']
  tag nist: ['AC-23']
end
