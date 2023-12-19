control 'SV-80919' do
  title 'The IDPS must send an alert to, at a minimum, the ISSO and ISSM when DoS incidents are detected.'
  desc %q(Without an alert, security personnel may be unaware of major detection incidents that require immediate action and this delay may result in the loss or compromise of information.

CJCSM 6510.01B, "Cyber Incident Handling Program", lists nine Cyber Incident and Reportable Event Categories. DoD has determined that categories identified by CJCSM 6510.01B Major Indicators (category I, II, IV, and VII detection events) will require an alert when an event is detected.

Alerts messages must include a severity level indicator or code as an indicator of the criticality of the incident. Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The IDPS must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel. The Juniper SRX IDPS can be configured for email alerts.)
  desc 'check', 'Verify alerts are configured to implement this requirement.

[edit]
show security alarms potential-violation

If alerts are not configured to notify the ISSO and ISSM of potential-violation IDP events, this is a finding.'
  desc 'fix', 'Configure alerts for IDP attack by using the [edit security alarms potential-violation] command.

Add the option "alert" onto the rule to send an alert when that rule is invoked. Alerts should be sent only on critical and other site-selected items to prevent an excess of alerts.

[edit]
set security idp idp-policy recommended rulebase-ips rule-1 then notification log-attacks alert'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG IDPS'
  tag check_id: 'C-67075r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66429'
  tag rid: 'SV-80919r1_rule'
  tag stig_id: 'JUSX-IP-000025'
  tag gtitle: 'SRG-NET-000392-IDPS-00218'
  tag fix_id: 'F-72505r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
