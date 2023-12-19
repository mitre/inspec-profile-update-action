control 'SV-207701' do
  title 'To protect against unauthorized data mining, the Palo Alto Networks security platform must detect and prevent code injection attacks launched against application objects including, at a minimum, application URLs and application code.'
  desc 'Data mining is the analysis of large quantities of data to discover patterns and is used in intelligence gathering. Failure to detect attacks that use unauthorized data mining techniques to attack applications may result in the compromise of information.

Injection attacks allow an attacker to inject code into a program or query or inject malware onto a computer to execute remote commands that can read or modify a database, or change data on a website. These attacks include buffer overrun, XML, JavaScript, and HTML injections.

IDPS component(s) with the capability to prevent code injections must be included in the IDPS implementation to protect against unauthorized data mining. These components must include rules and anomaly detection algorithms to monitor for atypical database queries or accesses.'
  desc 'check', 'Go to  Objects >> Security Profiles >> Vulnerability Protection.

If there are no Vulnerability Protection Profiles configured, this is a finding.'
  desc 'fix', 'Create and apply a Vulnerability Protection Profile to protect database assets by blocking and alerting on attacks. This example profile has two rules; the first blocks critical, high, and medium threats, and the second alerts on low and informational threats.

Creating the Protection Profiles:
1. Go to Objects >> Security Profiles >> Vulnerability Protection and select "Add".
2. In the "Vulnerability Protection Profile" window, complete the following required fields:
     In the "Name" field, enter the name of the Vulnerability Protection Profile.
     In the "Description" field, enter the description of the Vulnerability Protection Profile.
     In the "Rules" tab, select "Add".
3. In the "Vulnerability Protection Rule" window, complete the required fields:
     In the "Rule Name" field, enter the Rule name.
     In the "Threat Name" field, select "any".
     In the "Action" field, select "block".
     In the "Host type" field, select "server".
     Select the checkboxes above the "CVE" and "Vendor ID" boxes. 
    In the "Severity" section, select the "critical", "high", and "medium" check boxes.
    Select "OK".
4. In the "Vulnerability Protection Profile" window, select the configured rule, then select "OK".
5. Add a second rule that alerts on low and informational threats.

Apply the Vulnerability Protection Profile to the Security Policy Rules permitting traffic to the databases.
1. Go to Policies >> Security.
2. Select an existing policy rule.
3. In the "Actions" tab in the "Profile Setting" section; in the "Profile Type" field, select "Profiles". The window will change to display the different categories of Profiles.  
4. In the "Actions" tab in the "Profile Setting" section; in the "Vulnerability Protection" field, select the configured Vulnerability Protection Profile.
5. Select "OK". 

Commit changes by selecting "Commit" in the upper-right corner of the screen. Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks IDPS'
  tag check_id: 'C-7955r864177_chk'
  tag severity: 'medium'
  tag gid: 'V-207701'
  tag rid: 'SV-207701r864179_rule'
  tag stig_id: 'PANW-IP-000033'
  tag gtitle: 'SRG-NET-000318-IDPS-00182'
  tag fix_id: 'F-7955r864178_fix'
  tag 'documentable'
  tag legacy: ['SV-77163', 'V-62673']
  tag cci: ['CCI-002376']
  tag nist: ['RA-5 e']
end
