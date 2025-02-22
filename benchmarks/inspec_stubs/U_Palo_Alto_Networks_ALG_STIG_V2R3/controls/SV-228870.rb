control 'SV-228870' do
  title 'The Palo Alto Networks security platform must generate an alert to, at a minimum, the ISSO and ISSM when threats identified by authoritative sources (e.g., IAVMs or CTOs) are detected.'
  desc "Without an alert, security personnel may be unaware of major detection incidents that require immediate action, and this delay may result in the loss or compromise of information.

The device generates an alert that notifies designated personnel of the Indicators of Compromise (IOCs) that require real-time alerts. These messages should include a severity level indicator or code as an indicator of the criticality of the incident. These indicators reflect the occurrence of a compromise or a potential compromise. Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The Palo Alto Networks security platform must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel.

Current USSTRATCOM warning and tactical directives/orders include Fragmentary Order (FRAGO), Communications Tasking Orders (CTOs), IA Vulnerability Notices, Network Defense Tasking Message (NDTM), DOD GIG Tasking Message (DGTM), and Operations Order (OPORD)."
  desc 'check', 'Ask the Administrator how the ISSO and ISSM are receiving alerts (E-mail, SNMP Trap, or Syslog).

View the configured Server Profile, if there is no Server Profile for the method explained, this is a finding.
 
View the Log Forwarding Profiles; this is under Objects >> Log Forwarding.  Determine which Server Profile is associated with each Log Forwarding Profile.
View the Security Policies that are used to enforce policies issued by authoritative sources.
Go to Policies >> Security; select the name of the security policy to view it. 
In the Actions tab, in the Log Setting section, view the Log Forwarding Profile.  If there is no Log Forwarding Profile, this is a finding.'
  desc 'fix', 'Configure a Server Profile for use with Log Forwarding Profile(s); if email is used, the ISSO and ISSM must be recipients.
   
To create an email server profile:
Go to Device >> Server Profiles >> Email
Select "Add". 
In the Email Server Profile, enter the name of the profile.
Select "Add".
In the "Servers" tab, enter the required information:
In the "Name" field, enter the name of the Email server
In the "Email Display Name" field, enter the name shown in the From field of the email.
In the "From" field, enter the From email address.
In the "To" field, enter the email address of the recipient.
In the "Additional Recipient" field, enter the email address of another recipient. Only one additional recipient can be added. To add multiple recipients, add the email address of a distribution list.
In the "Gateway" field, enter the IP address or host name of the Simple Mail Transport Protocol (SMTP) server used to send the email.
Select the "OK" button.

Configure a Log Forwarding Profile:
Go to Objects >> Log Forwarding
Go to Policies >> Security
Select "Add" to create a new security policy or select the name of the security policy to edit it. 
Configure the specific parameters of the policy by completing the required information in the fields of each tab.
In the "Actions" tab, select the Log forwarding profile and select "Log at Session End".  "Log at Session Start" may be selected under specific circumstances, but "Log at Session End" is preferred.
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31105r513905_chk'
  tag severity: 'medium'
  tag gid: 'V-228870'
  tag rid: 'SV-228870r831612_rule'
  tag stig_id: 'PANW-AG-000118'
  tag gtitle: 'SRG-NET-000392-ALG-000142'
  tag fix_id: 'F-31082r513906_fix'
  tag 'documentable'
  tag legacy: ['SV-77111', 'V-62621']
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
