control 'SV-215776' do
  title 'To protect against data mining, the BIG-IP Core implementation providing content filtering must be configured to detect code injection attacks being launched against data storage objects.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks launched against organizational databases may result in the compromise of information.

Injection attacks allow an attacker to inject code into a program or query or inject malware into a computer to execute remote commands that can read or modify a database or change data on a website. Web applications frequently access databases to store, retrieve, and update information. An attacker can construct inputs that the database will execute. This is most commonly referred to as a code injection attack. This type of attack includes XPath and LDAP injections.

ALGs with anomaly detection must be configured to protect against unauthorized code injections. These devices must include rules and anomaly detection algorithms to monitor for atypical database queries or accesses. Examples include Web Application Firewalls (WAFs) or database application gateways.'
  desc 'check', 'If the BIG-IP Core does not perform content filtering as part of the traffic management functionality for virtual servers, this is not applicable.

When content filtering is performed as part of the traffic management functionality, verify the BIG-IP Core is configured as follows:

Verify Virtual Server(s) in the BIG-IP LTM module are configured with an ASM policy to detect code injection attacks being launched against data storage objects.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Navigate to the Security >> Policies tab.

Verify that "Application Security Policy" is Enabled and "Policy" is set to detect code injection attacks being launched against data storage objects.

If the BIG-IP Core is not configured to detect code injection attacks being launched against data storage objects, including, at a minimum, databases, database records, queries, and fields, this is a finding.'
  desc 'fix', 'If the BIG-IP Core performs content filtering as part of the traffic management functionality, configure the BIG-IP Core as follows:

Configure a policy in the BIG-IP ASM module to detect code injection attacks being launched against data storage objects.

Apply a policy to the applicable Virtual Server(s) in BIG-IP LTM module that was configured in the ASM module to detect code injection attacks being launched against data storage objects.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16968r291141_chk'
  tag severity: 'medium'
  tag gid: 'V-215776'
  tag rid: 'SV-215776r557356_rule'
  tag stig_id: 'F5BI-LT-000163'
  tag gtitle: 'SRG-NET-000319-ALG-000015'
  tag fix_id: 'F-16966r291142_fix'
  tag 'documentable'
  tag legacy: ['V-60333', 'SV-74763']
  tag cci: ['CCI-002347']
  tag nist: ['AC-23']
end
