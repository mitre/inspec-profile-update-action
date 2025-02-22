control 'SV-207714' do
  title 'The Palo Alto Networks security platform must send an alert to, at a minimum, the ISSO and ISSM when denial of service incidents are detected.'
  desc %q(Without an alert, security personnel may be unaware of major detection incidents that require immediate action and this delay may result in the loss or compromise of information.

CJCSM 6510.01B, "Cyber Incident Handling Program", lists nine Cyber Incident and Reportable Event Categories. DoD has determined that categories identified by CJCSM 6510.01B Major Indicators (category I, II, IV, and VII detection events) will require an alert when an event is detected.

Alert messages must include a severity level indicator or code as an indicator of the criticality of the incident. Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The Palo Alto Networks security platform must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel.)
  desc 'check', 'Ask the Administrator how the ISSO and ISSM are receiving alerts (E-mail, SNMP Trap, or Syslog).

View the configured Server Profile; if there is no Server Profile for the method explained, this is a finding.
 
View the Log Forwarding Profiles; this is under Objects >> Log Forwarding.  Determine which Server Profile is associated with each Log Forwarding Profile.
Go to Policies >> DoS Protection
If there are no DoS Protection Policies, this is a finding.

There may be more than one configured DoS Protection Policy.
If there is no such DoS Protection Policy, this is a finding.

In the "Log Forwarding" field, if there is no configured Log Forwarding Profile, this is a finding.'
  desc 'fix', 'Configure a Server Profile for use with Log Forwarding Profile(s);  If email is used, the ISSO and ISSM must be recipients.   
Configure a Log Forwarding Profile; this is under Objects >> Log Forwarding.
Go to Policies >> DoS Protection
Select "Add" to create a new policy or select the Name of the Policy to edit it.
In the "DoS Rule" window, complete the required fields.
In the "Option/Protection" tab, in the "Log Forwarding" field, select the configured Log Forwarding Profile.
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.  Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks IDPS'
  tag check_id: 'C-7968r358475_chk'
  tag severity: 'medium'
  tag gid: 'V-207714'
  tag rid: 'SV-207714r856628_rule'
  tag stig_id: 'PANW-IP-000055'
  tag gtitle: 'SRG-NET-000392-IDPS-00218'
  tag fix_id: 'F-7968r358476_fix'
  tag 'documentable'
  tag legacy: ['SV-77189', 'V-62699']
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
