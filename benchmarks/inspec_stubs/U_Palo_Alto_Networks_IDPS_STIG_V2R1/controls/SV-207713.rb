control 'SV-207713' do
  title 'The Palo Alto Networks security platform must generate an alert to, at a minimum, the ISSO and ISSM when rootkits or other malicious software which allows unauthorized privileged or non-privileged access is detected.'
  desc %q(Without an alert, security personnel may be unaware of major detection incidents that require immediate action and this delay may result in the loss or compromise of information.

CJCSM 6510.01B, "Cyber Incident Handling Program", lists nine Cyber Incident and Reportable Event Categories. DoD has determined that categories identified by CJCSM 6510.01B Major Indicators (category I, II, IV, and VII detection events) will require an alert when an event is detected.

Alert messages must include a severity level indicator or code as an indicator of the criticality of the incident. Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The Palo Alto Networks security platform  must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel.)
  desc 'check', 'Ask the Administrator how the ISSO and ISSM are receiving alerts (E-mail, SNMP Trap, or Syslog).

View the configured Server Profile; if there is no Server Profile for the method explained, this is a finding.
 
View the Log Forwarding Profiles; this is under Objects >> Log Forwarding.  Determine which Server Profile is associated with each Log Forwarding Profile.
View the Security Policies that are used to filter traffic into the Internal or DMZ zones.

If the "Profile" column does not display the Antivirus Profile symbol, this is a finding.

If the "Profile" column does not display the Vulnerability Protection Profile symbol, this is a finding.
  
If the "Profile" column does not display the Anti-spyware symbol, this is a finding.

If the "Options" column does not display the Log Forwarding Profile symbol, this is a finding.'
  desc 'fix', 'This requires the use of an Antivirus Profile, an Anti-spyware Profile, and a Vulnerability Protection Profile.

Configure a Server Profile for use with Log Forwarding Profile(s);  If email is used, the ISSO and ISSM must be recipients.   
Configure a Log Forwarding Profile; this is under Objects >> Log Forwarding.
Configure an Antivirus Profile, an Anti-spyware Profile, and a Vulnerability Protection Profile in turn.
Note: A custom Anti-spyware Profile or the Strict Anti-spyware Profile must be used instead of the Default Anti-spyware Profile.  The selected Anti-spyware Profile must use the block action at the critical, high, and medium severity threat levels.
  
Use the Antivirus Profile, Anti-spyware Profile, and the Vulnerability Protection Profile in a Security Policy that filters traffic to Internal and DMZ zones:
Go to Policies >> Security
Select an existing policy rule or select "Add" to create a new one.
In the "Actions" tab in the "Profile Setting" section; in the "Profile Type" field, select "Profiles".  The window will change to display the different categories of Profiles.  
In the "Actions" tab in the "Profile Setting" section; in the "Antivirus" field, select the configured Antivirus Profile.
In the "Actions" tab in the "Profile Setting" section; in the "Anti-spyware" field, select the configured or "Strict Anti-spyware" Profile.
In the "Actions" tab in the "Profile Setting" section; in the "Vulnerability Protection" field, select the configured Vulnerability Protection Profile.
In the "Actions" tab in the "Log Setting" section, select "Log At Session End".  This generates a traffic log entry for the end of a session and logs drop and deny entries.  
In the "Actions" tab in the "Log Setting" section; in the "Log Forwarding" field, select the log forwarding profile from drop-down list.
Select "OK". 
Commit changes by selecting "Commit" in the upper-right corner of the screen.  Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks IDPS'
  tag check_id: 'C-7967r358472_chk'
  tag severity: 'medium'
  tag gid: 'V-207713'
  tag rid: 'SV-207713r557390_rule'
  tag stig_id: 'PANW-IP-000053'
  tag gtitle: 'SRG-NET-000392-IDPS-00216'
  tag fix_id: 'F-7967r358473_fix'
  tag 'documentable'
  tag legacy: ['V-62697', 'SV-77187']
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
