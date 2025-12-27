control 'SV-215773' do
  title 'To protect against data mining, the BIG-IP Core implementation must be configured to prevent code injection attacks from being launched against data storage objects, including, at a minimum, databases, database records, queries, and fields when providing content filtering to virtual servers.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to prevent attacks launched against organizational information from unauthorized data mining may result in the compromise of information.

Injection attacks allow an attacker to inject code into a program or query or inject malware into a computer to execute remote commands that can read or modify a database or change data on a website. Web applications frequently access databases to store, retrieve, and update information. An attacker can construct inputs that the database will execute. This is most commonly referred to as a code injection attack. This type of attack includes XPath and LDAP injections.

Compliance requires the ALG to have the capability to prevent code injections. Examples include Web Application Firewalls (WAFs) or database application gateways.'
  desc 'check', 'If the BIG-IP Core does not perform content filtering as part of the traffic management functionality for virtual servers, this is not applicable.

When  content filtering is performed as part of the traffic management functionality, verify the BIG-IP Core is configured as follows:

Verify Virtual Server(s) in the BIG-IP LTM module are configured with an ASM policy to prevent code injection attacks from being launched against data storage objects, including, at a minimum, databases, database records, queries, and fields.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Navigate to the Security >> Policies tab.

Verify that "Application Security Policy" is Enabled and "Policy" is set to use an ASM policy to prevent code injection attacks from being launched against data storage objects, including, at a minimum, databases, database records, queries, and fields when providing content filtering to virtual servers.

If the BIG-IP Core is not configured to prevent code injection attacks from being launched against data storage objects, including, at a minimum, databases, database records, queries, and fields, this is a finding.'
  desc 'fix', 'If the BIG-IP Core performs content filtering as part of the traffic management functionality, configure the BIG-IP Core as follows:

Configure a policy in the BIG-IP ASM module to prevent code injection attacks from being launched against data storage objects, including, at a minimum, databases, database records, queries, and fields.

Apply ASM policy to the applicable Virtual Server(s) in BIG-IP LTM module to prevent code injection attacks from being launched against data storage objects, including, at a minimum, databases, database records, queries, and fields when providing content filtering to virtual servers.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16965r291132_chk'
  tag severity: 'medium'
  tag gid: 'V-215773'
  tag rid: 'SV-215773r557356_rule'
  tag stig_id: 'F5BI-LT-000157'
  tag gtitle: 'SRG-NET-000318-ALG-000014'
  tag fix_id: 'F-16963r291133_fix'
  tag 'documentable'
  tag legacy: ['SV-74757', 'V-60327']
  tag cci: ['CCI-002346']
  tag nist: ['AC-23']
end
