control 'SV-228871' do
  title 'The Palo Alto Networks security platform must generate an alert to, at a minimum, the ISSO and ISSM when rootkits or other malicious software which allows unauthorized privileged access is detected.'
  desc %q(Without an alert, security personnel may be unaware of major detection incidents that require immediate action, and this delay may result in the loss or compromise of information.

The Palo Alto Networks security platform generates an alert that notifies designated personnel of the Indicators of Compromise (IOCs) that require real-time alerts. These messages should include a severity level indicator or code as an indicator of the criticality of the incident. These indicators reflect the occurrence of a compromise or a potential compromise.

Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

CJCSM 6510.01B, "Cyber Incident Handling Program", lists nine Cyber Incident and Reportable Event Categories. DoD has determined that categories identified by CJCSM 6510.01B Major Indicators (category 1, 2, 4, or 7 detection events) will require an alert when an event is detected.

Category 1; Root Level Intrusion (Incident)-Unauthorized privileged access to an IS.
Category 4; Malicious Logic (Incident)-Installation of software designed and/or deployed by adversaries with malicious intentions for the purpose of gaining access to resources or information without the consent or knowledge of the user.

Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The Palo Alto Networks security platform must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel.)
  desc 'check', 'Ask the Administrator how the ISSO and ISSM are receiving alerts (E-mail, SNMP Trap, or Syslog).
View the configured Server Profile, if there is no Server Profile for the method explained, this is a finding.

View the Log Forwarding Profiles:
Go to Objects >> Log Forwarding
Determine which Server Profile is associated with each Log Forwarding Profile.
View the Security Policies that are used to filter traffic into the Internal or DMZ zones.

If the "Profile" column does not display the "Antivirus Profile" symbol, this is a finding.
If the "Profile" column does not display the "Vulnerability Protection Profile" symbol, this is a finding.
If the "Profile" column does not display the "Anti-spyware" symbol (which looks like a magnifying glass on a shield), this is a finding.
If the "Options" column does not display the "Log Forwarding Profile" symbol, this is a finding.'
  desc 'fix', 'This requires the use of an Antivirus Profile, an Anti-spyware Profile, and a Vulnerability Protection Profile.
Configure a Server Profile for use with Log Forwarding Profile(s); if email is used, the ISSO and ISSM must be recipients.

Configure a Log Forwarding Profile:
Go to Objects >> Log Forwarding
Configure an Antivirus Profile, an Anti-spyware Profile, and a Vulnerability Protection Profile in turn.  Note: A custom Anti-spyware Profile or the Strict Anti-spyware Profile must be used instead of the Default Anti-spyware Profile.  The selected Anti-spyware Profile must use the block action at the critical, high, and medium severity threat levels.  
Use the Antivirus Profile, Anti-spyware Profile, and the Vulnerability Protection Profile in a Security Policy that filters traffic to Internal and DMZ zones;
Go to Policies >> Security
Select an existing policy rule or select "Add" to create a new one.
In the "Actions" tab in the "Profile Setting" section; in the "Profile Type" field, select "Profiles".  The window will change to display the different categories of Profiles.  
In the "Actions" tab in the "Profile Setting" section; in the "Antivirus" field, select the configured Antivirus Profile.
In the "Actions" tab in the "Profile Setting" section; in the "Anti-spyware" field, select the configured or Strict Anti-spyware Profile.
In the "Actions" tab in the "Profile Setting" section; in the "Vulnerability Protection" field, select the configured Vulnerability Protection Profile.
In the "Actions" tab in the "Log Setting" section, select "Log At Session End".  This generates a traffic log entry for the end of a session and logs drop and deny entries.  
In the "Actions" tab in the "Log Setting" section; in the "Log Forwarding field", select the log forwarding profile from drop-down list.
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31106r513908_chk'
  tag severity: 'medium'
  tag gid: 'V-228871'
  tag rid: 'SV-228871r557387_rule'
  tag stig_id: 'PANW-AG-000119'
  tag gtitle: 'SRG-NET-000392-ALG-000143'
  tag fix_id: 'F-31083r513909_fix'
  tag 'documentable'
  tag legacy: ['SV-77113', 'V-62623']
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
