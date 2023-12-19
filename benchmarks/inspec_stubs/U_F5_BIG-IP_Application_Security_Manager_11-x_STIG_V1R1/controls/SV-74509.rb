control 'SV-74509' do
  title 'To protect against data mining, The BIG-IP ASM module must be configured to prevent SQL injection attacks launched against data storage objects, including, at a minimum, databases, database records, and database fields when providing content filtering to virtual servers.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to prevent attacks launched against organizational information from unauthorized data mining may result in the compromise of information.

SQL injection attacks are the most prevalent attacks against web applications and databases. These attacks inject SQL commands that can read, modify, or compromise the meaning of the original SQL query. An attacker can spoof identity; expose, tamper, destroy, or make existing data unavailable; or gain unauthorized privileges on the database server.

Compliance requires the ALG to have the capability to prevent SQL code injections. Examples include Web Application Firewalls (WAFs) or database application gateways.'
  desc 'check', 'If the BIG-IP ASM module is not used to support content filtering as part of the traffic management functions of the BIG-IP Core, this is not applicable.

Verify the BIG-IP ASM module is configured to prevent SQL injection attacks launched against data storage objects, including, at a minimum, databases, database records, and database fields.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify the configuration of an ASM policy to prevent SQL injection attacks.

Navigate to the Security >> Policies tab.

Set "Policy Settings" to "Advanced".

Verify that "Application Security Policy" is Enabled and "Policy" is set to use an ASM policy for the virtual server.

Navigate to the BIG-IP System manager >> Security >> Application Security >> Security Policies.

Select the Security Policy that has been assigned the Virtual Server(s).

Verify the "Enforcement Mode" is Blocking.

Click "Attack Signatures Configurations" for "Signature Staging" under the "Configuration" section.

Verify "Signature Staging" is Enabled.

Review the list under "Assigned Signature Sets" for the following signatures:

Generic Detection Signatures

Custom Systems Signature Set (based on systems identified in the application make-up).

Verify the "Assigned Signature Sets" listed above have the "Block" button checked.

If the BIG-IP ASM module is not configured to prevent SQL injection attacks from being launched against data storage objects, including, at a minimum, databases, database records, and database fields, this is a finding.'
  desc 'fix', 'If the BIG-IP ASM module is used to support content filtering as part of the traffic management functionality of the BIG-IP Core, configure the BIG-IP ASM module to prevent SQL injection attacks launched against data storage objects, including, at a minimum, databases, database records, and database fields.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP ASM 11.x'
  tag check_id: 'C-60841r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60079'
  tag rid: 'SV-74509r1_rule'
  tag stig_id: 'F5BI-AS-000161'
  tag gtitle: 'SRG-NET-000318-ALG-000152'
  tag fix_id: 'F-65573r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002346']
  tag nist: ['AC-23']
end
