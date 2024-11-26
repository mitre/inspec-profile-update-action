control 'SV-207701' do
  title 'To protect against unauthorized data mining, the Palo Alto Networks security platform must detect and prevent code injection attacks launched against application objects including, at a minimum, application URLs and application code.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks that use unauthorized data mining techniques to attack applications may result in the compromise of information.

Injection attacks allow an attacker to inject code into a program or query or inject malware onto a computer to execute remote commands that can read or modify a database, or change data on a website. These attacks include buffer overrun, XML, JavaScript, and HTML injections.

IDPS component(s) with the capability to prevent code injections must be included in the IDPS implementation to protect against unauthorized data mining. These components must include rules and anomaly detection algorithms to monitor for atypical database queries or accesses.'
  desc 'check', 'Go to  Objects >> Security Profiles >> Vulnerability Protection

If there are no Vulnerability Protection Profiles configured, this is a finding.

Ask the Administrator which Vulnerability Protection Profile is used to protect application assets by blocking and alerting on attacks.
View the configured Vulnerability Protection Profile; check the "Severity" and "Action" columns.

If the Vulnerability Protection Profile used for database protection does not block all critical, high, and medium threats, this is a finding.

If the Vulnerability Protection Profile used for database protection does not alert on low and informational threats, this is a finding.

Ask the Administrator which Security Policy is used to protect application assets.
Go to Policies >> Security
View the configured Security Policy; view the "Profile" column.
 
If the "Profile" column does not display the Vulnerability Protection Profile symbol, this is a finding.

Moving the cursor over the symbol will list the exact Vulnerability Protection Profiles applied.

If the specific Vulnerability Protection Profile is not listed, this is a finding.'
  desc 'fix', 'Set a unique hostname.
Go to Device >> Setup >> Management
In the "General Settings" window, select the "Edit" icon (the gear symbol in the upper-right corner of the pane).
In the "General Settings" window, in the "hostname" field; enter a unique hostname.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks IDPS'
  tag check_id: 'C-7955r358436_chk'
  tag severity: 'medium'
  tag gid: 'V-207701'
  tag rid: 'SV-207701r557390_rule'
  tag stig_id: 'PANW-IP-000033'
  tag gtitle: 'SRG-NET-000318-IDPS-00182'
  tag fix_id: 'F-7955r358437_fix'
  tag 'documentable'
  tag legacy: ['SV-77163', 'V-62673']
  tag cci: ['CCI-002346']
  tag nist: ['AC-23']
end
