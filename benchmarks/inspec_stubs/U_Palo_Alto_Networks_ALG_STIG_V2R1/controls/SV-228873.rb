control 'SV-228873' do
  title 'The Palo Alto Networks security platform must generate an alert to, at a minimum, the ISSO and ISSM when denial of service incidents are detected.'
  desc 'Without an alert, security personnel may be unaware of major detection incidents that require immediate action, and this delay may result in the loss or compromise of information.

CJCSM 6510.01B, "Cyber Incident Handling Program", lists nine Cyber Incident and Reportable Event Categories. DoD has determined that categories identified by CJCSM 6510.01B Major Indicators (category 1, 2, 4, or 7 detection events) will require an alert when an event is detected.

Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The Palo Alto Networks security platform must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel.  Configure a Server Profile for use with Log Forwarding Profile(s);if email is used, the ISSO and ISSM must be recipients.'
  desc 'check', 'Ask the Administrator how the ISSO and ISSM are receiving alerts (email, SNMP Trap, or Syslog).
View the configured Server Profile:
Go to Device >> Server Profiles; if there is no Server Profile for the method explained, this is a finding.

View the Log Forwarding Profiles:
Go to Objects >> Log Forwarding
Determine which Server Profile is associated with each Log Forwarding Profile.
If there are no Log Forwarding Profiles configured, this is a finding.
Go to Policies >> DoS Protection
If there are no DoS Protection Policies, this is a finding. There may be more than one configured DoS Protection Policy.
If there is no such DoS Protection Policy, this is a finding.
In the "Log Forwarding" field, if there is no configured Log Forwarding Profile, this is a finding.

Alternately, a Zone Protection Profile can be used either instead of or in addition to a DoS Protection Policy.
Ask the Administrator how the ISSO and ISSM are receiving alerts (E-mail, SNMP Trap, or Syslog).
View the configured Server Profile, if there is no Server Profile for the method explained, this is a finding.
View the Log Forwarding Profiles:
Go to Objects >> Log Forwarding
Determine which Server Profile is associated with each Log Forwarding Profile.'
  desc 'fix', 'Configure a Log Forwarding Profile:
Go to Objects >> Log Forwarding
Go to Policies >> DoS Protection
Select "Add" to create a new policy or select the Name of the Policy to edit it.
In the "DoS Rule" Window, complete the required fields.
In the "Option/Protection" tab, in the "Log Forwarding" field, select the configured Log Forwarding Profile.
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.

Alternately, a Zone Protection Profile can be used either instead of or in addition to a DoS Protection Policy.
Go to Network>>Zone
Select “Add” or select an existing Zone.
In the Zone window, in the Zone Protection Profile field, select or create a Zone Protection Profile.
Configure the applicable fields in the Flood Protection, Reconnaissance Protection, and Packet Based Attack Protection as needed.
In the Zone window, in the Log Setting field, select a configured log forwarding profile.
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31108r513914_chk'
  tag severity: 'medium'
  tag gid: 'V-228873'
  tag rid: 'SV-228873r557387_rule'
  tag stig_id: 'PANW-AG-000121'
  tag gtitle: 'SRG-NET-000392-ALG-000148'
  tag fix_id: 'F-31085r513915_fix'
  tag 'documentable'
  tag legacy: ['SV-77117', 'V-62627']
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
