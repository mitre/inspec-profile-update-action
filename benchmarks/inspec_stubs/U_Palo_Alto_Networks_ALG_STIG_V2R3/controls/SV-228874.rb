control 'SV-228874' do
  title 'The Palo Alto Networks security platform must generate an alert to, at a minimum, the ISSO and ISSM when new active propagation of malware infecting DoD systems or malicious code adversely affecting the operations and/or security of DoD systems is detected.'
  desc %q(Without an alert, security personnel may be unaware of major detection incidents that require immediate action, and this delay may result in the loss or compromise of information.

The device generates an alert that notifies designated personnel of the Indicators of Compromise (IOCs) that require real-time alerts. These messages should include a severity level indicator or code as an indicator of the criticality of the incident. These indicators reflect the occurrence of a compromise or a potential compromise.
Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

CJCSM 6510.01B, "Cyber Incident Handling Program", lists nine Cyber Incident and Reportable Event Categories. DoD has determined that categories identified by CJCSM 6510.01B Major Indicators (category 1, 2, 4, or 7 detection events) will require an alert when an event is detected.

Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The Palo Alto Networks security platform must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel.)
  desc 'check', 'Ask the Administrator how the ISSO and ISSM are receiving alerts (E-mail, SNMP Trap, or Syslog).

View the configured Server Profile, if there is no Server Profile for the method explained, this is a finding.

View the Log Forwarding Profiles:
Go to Objects >> Log Forwarding
Determine which Server Profile is associated with each Log Forwarding Profile.
View the Security Policies that are used to filter traffic between zones or subnets.

If the "Profile" column does not display the "Antivirus Profile" symbol, this is a finding.

If the "Options" column does not display the "Log Forwarding Profile" symbol, this is a finding.'
  desc 'fix', 'Configure a Server Profile for use with Log Forwarding Profile(s);  if email is used, the ISSO and ISSM must be recipients.
   
Configure a Log Forwarding Profile:
Go to Objects >> Log Forwarding
Go to Objects >> Security Profiles >> Antivirus
Select "Add" to create a new Antivirus Profile or select the name of the profile to edit it.

Use the Antivirus Profile in a Security Policy:
Go to Policies >> Security
Select an existing policy rule or select "Add" to create a new one.
In the "Actions" tab in the "Profile Setting" section; in the "Profile Type" field, select "Profiles".  The window will change to display the different categories of Profiles.  
In the "Actions" tab in the "Profile Setting" section; in the "Antivirus" field, select the configured Antivirus Profile.
Select "OK".

In the "Actions" tab in the "Log Setting" section, select "Log At Session End".  
In the "Actions" tab in the "Log Setting" section; in the "Log Forwarding" field, select the log forwarding profile from drop-down list.
Select "OK".

Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31109r513917_chk'
  tag severity: 'medium'
  tag gid: 'V-228874'
  tag rid: 'SV-228874r831616_rule'
  tag stig_id: 'PANW-AG-000122'
  tag gtitle: 'SRG-NET-000392-ALG-000149'
  tag fix_id: 'F-31086r513918_fix'
  tag 'documentable'
  tag legacy: ['V-62629', 'SV-77119']
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
