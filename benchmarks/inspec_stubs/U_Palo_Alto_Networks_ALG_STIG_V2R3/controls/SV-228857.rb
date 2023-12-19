control 'SV-228857' do
  title 'To protect against data mining, the Palo Alto Networks security platform must detect and prevent code injection attacks launched against application objects including, at a minimum, application URLs and application code.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to prevent attacks launched against organizational information from unauthorized data mining may result in the compromise of information.

Injection attacks allow an attacker to inject code into a program or query or inject malware onto a computer to execute remote commands that can read or modify a database or change data on a website. These attacks include buffer overrun, XML, JavaScript, and HTML injections.

Most current applications are deployed as a multi-tier architecture. The multi-tier model uses separate server machines to provide the different functions of presentation, business logic, and database.  The multi-tier architecture provides added security because a compromised web server does not provide direct access to the application itself or to the database.'
  desc 'check', 'Go to  Objects >> Security Profiles >> Vulnerability Protection
If there are no Vulnerability Protection Profiles configured, this is a finding.

Ask the Administrator which Vulnerability Protection Profile is used to protect application assets by blocking and alerting on attacks.
View the configured Vulnerability Protection Profile; check the "Severity" and "Action" columns.
If the Vulnerability Protection Profile used for database protection does not block all critical, high, and medium threats, this is a finding.

If the Vulnerability Protection Profile used for database protection does not alert on low and informational threats, this is a finding.

Ask the Administrator which Security Policy is used to protect application assets:
Go to Policies >> Security
View the configured Security Policy; view the "Profile" column.
If the "Profile" column does not display the "Vulnerability Protection Profile" symbol, this is a finding.

Moving the cursor over the symbol will list the exact Vulnerability Protection Profiles applied.

If the specific Vulnerability Protection Profile is not listed, this is a finding.'
  desc 'fix', 'Create and apply a Vulnerability Protection Profile to protect application assets by blocking and alerting on attacks. This profile has two rules; the first blocks critical, high, and medium threats, and the second alerts on low and informational threats.
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
In the "Host type" field, select "server".
Select the check boxes above the "CVE" and "Vendor ID" boxes. 
In the "Severity" section, select the "critical", "high", and "medium" check boxes.
Select "OK".
In the "Vulnerability Protection Profile" window, select the configured rule, then select "OK".
Add a second rule that  alerts on low and informational threats.
Apply the Vulnerability Protection Profile to the Security Policy Rules permitting traffic to the applications.
Go to Policies >> Security
Select an existing policy rule or select "Add" to create a new one.
In the "Actions" tab in the "Profile Setting" section; in the "Profile Type" field, select "Profiles".  The window will change to display the different categories of Profiles.  
In the "Actions" tab in the "Profile Setting" section; in the "Vulnerability Protection" field, select the configured Vulnerability Protection Profile.
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31092r513866_chk'
  tag severity: 'medium'
  tag gid: 'V-228857'
  tag rid: 'SV-228857r831597_rule'
  tag stig_id: 'PANW-AG-000081'
  tag gtitle: 'SRG-NET-000318-ALG-000151'
  tag fix_id: 'F-31069r513867_fix'
  tag 'documentable'
  tag legacy: ['V-62595', 'SV-77085']
  tag cci: ['CCI-002346']
  tag nist: ['AC-23']
end
