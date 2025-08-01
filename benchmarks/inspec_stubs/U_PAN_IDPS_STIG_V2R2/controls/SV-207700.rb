control 'SV-207700' do
  title 'To protect against unauthorized data mining, the Palo Alto Networks security platform must detect and prevent SQL and other code injection attacks launched against data storage objects, including, at a minimum, databases, database records, queries, and fields.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks that use unauthorized data mining techniques to attack databases may result in the compromise of information.

Injection attacks allow an attacker to inject code into a program or query or inject malware onto a computer to execute remote commands that can read or modify a database, or change data on a website. Web applications frequently access databases to store, retrieve, and update information. An attacker can construct inputs that the database will execute. This is most commonly referred to as a code injection attack. This type of attack includes XPath and LDAP injections.

IDPS component(s) with the capability to prevent code injections must be included in the IDPS implementation to protect against unauthorized data mining. These components must include rules and anomaly detection algorithms to monitor for atypical database queries or accesses.'
  desc 'check', 'Go to  Objects >> Security Profiles >> Vulnerability Protection
If there are no Vulnerability Protection Profiles configured, this is a finding.

Ask the Administrator which Vulnerability Protection Profile is used to protect database assets by blocking and alerting on attacks.
View the configured Vulnerability Protection Profile; check the "Severity" and "Action" columns.

If the Vulnerability Protection Profile used for database protection does not block all critical, high, and medium threats, this is a finding.

If the Vulnerability Protection Profile used for database protection does not alert on low and informational threats, this is a finding.

Ask the Administrator which Security Policy is used to protect database assets.
Go to Policies >> Security
View the configured Security Policy; view the "Profile" column.
 
If the "Profile" column does not display the Vulnerability Protection Profile symbol, this is a finding.

Moving the cursor over the symbol will list the exact Vulnerability Protection Profiles applied.

If the specific Vulnerability Protection Profile is not listed, this is a finding.'
  desc 'fix', 'Create and apply a Vulnerability Protection Profile to protect database assets by blocking and alerting on attacks. This profile has two rules; the first blocks critical, high, and medium threats, and the second alerts on low and informational threats.
Go to Objects >> Security Profiles >> Vulnerability Protection
Select "Add".
In the "Vulnerability Protection Profile" window, complete the required fields.
In the "Name" field, enter the name of the Vulnerability Protection Profile.
In the "Description" field, enter the description of the Vulnerability Protection Profile.
In the "Rules" tab, select "Add".
In the "Vulnerability Protection Rule" window, 
In the "Rule Name" field, enter the Rule name,
In the "Threat Name" field, select "any",
In the "Action" field, select "block".
In the "Host type" field, select "server",
Select the checkboxes above the "CVE" and "Vendor ID" boxes. 
In the "Severity" section, select the "critical", "high", and "medium" check boxes.
Select "OK".

In the "Vulnerability Protection Profile" window, select the configured rule, then select "OK".
Add a second rule that  alerts on low and informational threats.

Apply the Vulnerability Protection Profile to the Security Policy Rules permitting traffic to the databases.
Go to Policies >> Security
Select an existing policy rule or select "Add" to create a new one.
In the "Actions" tab in the "Profile Setting" section; in the "Profile Type" field, select "Profiles".  The window will change to display the different categories of Profiles.  
In the "Actions" tab in the "Profile Setting" section; in the "Vulnerability Protection" field, select the configured Vulnerability Protection Profile.
Select "OK". 
Commit changes by selecting "Commit" in the upper-right corner of the screen.  Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks IDPS'
  tag check_id: 'C-7954r358433_chk'
  tag severity: 'medium'
  tag gid: 'V-207700'
  tag rid: 'SV-207700r557390_rule'
  tag stig_id: 'PANW-IP-000032'
  tag gtitle: 'SRG-NET-000318-IDPS-00068'
  tag fix_id: 'F-7954r358434_fix'
  tag 'documentable'
  tag legacy: ['SV-77161', 'V-62671']
  tag cci: ['CCI-002346']
  tag nist: ['AC-23']
end
