control 'SV-207696' do
  title 'The Palo Alto Networks security platform must send an immediate (within seconds) alert to, at a minimum, the SA when malicious code is detected.'
  desc 'Without an alert, security personnel may be unaware of an impending failure of the audit capability, and the ability to perform forensic analysis and detect rate-based and other anomalies will be impeded.

The IDPS generates an immediate (within seconds) alert which notifies designated personnel of the incident. Sending a message to an unattended log or console does not meet this requirement since that will not be seen immediately. These messages should include a severity level indicator or code as an indicator of the criticality of the incident.

When the Palo Alto Networks security platform blocks malicious code, it also generates a record in the threat log.  This message has a medium severity.'
  desc 'check', 'The following is an example of how to check if the device is sending messages to e-mail; this is one option that meets the requirement.  If sending messages to an SNMP server or Syslog servers is used, follow the vendor guidance on how to verify that function.   
Go to Device >> Server Profiles >> Email
If there is no Email Server Profile configured, this is a finding.

Go to Objects >> Log forwarding
If there is no Email Forwarding Profile configured, this is a finding.

Go to Policies >> Security
View the Security Policy that is used to detect malicious code (the "Profile" column does display the Antivirus Profile symbol); in the "Options" column, if the Email Forwarding Profile is not used, this is a finding.'
  desc 'fix', 'The following is an example of how to configure the device to send messages to e-mail; this is one option that meets the requirement.  If sending messages to an SNMP server or Syslog servers is used, follow the vendor guidance on how to configure that function.

To create an email server profile:
Go to Device >> Server Profiles >> Email
Select "Add". 
In the "Email Server Profile" field, enter the name of the profile.
Select "Add".
In the "Servers" tab, enter the required information.
In the "Name" field, enter the name of the Email server.
In the "Email Display" Name field, enter the name shown in the "From" field of the email.
In the "From" field, enter the "From email address".
In the "To" field, enter the email address of the recipient.
In the "Additional Recipient" field, enter the email address of another recipient. You can only add one additional recipient. To add multiple recipients, add the email address of a distribution list.
In the "Gateway" field, enter the IP address or host name of the Simple Mail Transport Protocol (SMTP) server used to send the email.
Select "OK".

After you create the Server Profiles that define where to send your logs, you must enable log forwarding. 
Threat Logs—Enable forwarding of Threat logs by creating a Log Forwarding Profile (Objects >> Log Forwarding) that specifies which severity levels you want to forward and then adding it to the security policies for which you want to trigger the log forwarding. A Threat log entry will only be created (and therefore forwarded) if the associated traffic matches a Security Profile (Antivirus, Anti-spyware, Vulnerability, URL Filtering, File Blocking, Data Filtering, or DoS Protection).

Configure the log-forwarding profile to select the logs to be forwarded to Email server.
Go to Objects >> Log forwarding
The "Log Forwarding Profile" window appears.  Note that it has five columns.  
In the "Name" Field, enter the name of the Log Forwarding Profile.
In the "Threat Settings Section" in the "Email" column, select the Email server profile for forwarding threat logs to the configured server(s).
Select "OK".

When the "Log Forwarding Profile" window disappears, the screen will show the configured log-forwarding profile.
For Threat Logs, use the log forwarding profile in the security rules.
Go to Policies >> Security Rule
Select the rule for which the log forwarding needs to be applied, which in this case is the Security Policy that is used to detect malicious code (the "Profile column" does display the Antivirus Profile symbol). Apply the log forwarding profile to the rule.
In the "Actions" tab in the "Log Setting" section; in the "Log Forwarding" field, select the log forwarding profile from drop-down list.  Note that the "Log Forwarding" field can only have one profile.
Commit changes by selecting "Commit" in the upper-right corner of the screen.  Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks IDPS'
  tag check_id: 'C-7950r358421_chk'
  tag severity: 'medium'
  tag gid: 'V-207696'
  tag rid: 'SV-207696r557390_rule'
  tag stig_id: 'PANW-IP-000028'
  tag gtitle: 'SRG-NET-000249-IDPS-00222'
  tag fix_id: 'F-7950r358422_fix'
  tag 'documentable'
  tag legacy: ['SV-77153', 'V-62663']
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
