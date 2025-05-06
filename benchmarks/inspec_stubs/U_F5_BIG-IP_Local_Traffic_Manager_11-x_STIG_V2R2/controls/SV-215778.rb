control 'SV-215778' do
  title 'The BIG-IP Core implementation must be configured to detect code injection attacks being launched against application objects, including, at a minimum, application URLs and application code, when providing content filtering to virtual servers.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks launched against organizational applications may result in the compromise of information.

Injection attacks allow an attacker to inject code into a program or query or inject malware into a computer to execute remote commands that can read or modify a database or change data on a website. These attacks include buffer overrun, XML, JavaScript, and HTML injections.

ALGs with anomaly detection must be configured to protect against unauthorized code injections. These devices must include rules and anomaly detection algorithms to monitor for atypical database queries or accesses. Examples include Web Application Firewalls (WAFs) or database application gateways.'
  desc 'check', 'If the BIG-IP Core does not perform content filtering as part of the traffic management functionality for virtual servers, this is not applicable.

When content filtering is performed as part of the traffic management functionality, verify the BIG-IP Core is configured as follows:

Verify Virtual Server(s) in the BIG-IP LTM module are configured with an ASM policy to detect code injection attacks being launched against application objects, including, at a minimum, application URLs and application code.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Navigate to the Security >> Policies tab.

Verify that "Application Security Policy" is Enabled and "Policy" is set to detect code injection attacks being launched against application objects, including, at a minimum, application URLs and application code, when providing content filtering to virtual servers.

If the BIG-IP Core is not configured to detect code injection attacks from being launched against application objects, including, at a minimum, application URLs and application code, this is a finding.'
  desc 'fix', 'If the BIG-IP Core performs content filtering as part of the traffic management functionality, configure the BIG-IP Core as follows:

Configure a policy in the BIG-IP ASM module to detect code injection attacks being launched against application objects, including, at a minimum, application URLs and application code.

Apply ASM policy to the applicable Virtual Server(s) in BIG-IP LTM module to detect code injection attacks being launched against application objects, including, at a minimum, application URLs and application code, when providing content filtering to virtual servers.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16970r291147_chk'
  tag severity: 'medium'
  tag gid: 'V-215778'
  tag rid: 'SV-215778r831466_rule'
  tag stig_id: 'F5BI-LT-000167'
  tag gtitle: 'SRG-NET-000319-ALG-000153'
  tag fix_id: 'F-16968r291148_fix'
  tag 'documentable'
  tag legacy: ['SV-74767', 'V-60337']
  tag cci: ['CCI-002347']
  tag nist: ['AC-23']
end
