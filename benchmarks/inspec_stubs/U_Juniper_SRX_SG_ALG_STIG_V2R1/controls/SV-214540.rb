control 'SV-214540' do
  title 'The Juniper SRX Services Gateway Firewall must generate an alert that can be forwarded to, at a minimum, the ISSO and ISSM when threats identified by authoritative sources are detected.'
  desc "Without an alert, security personnel may be unaware of major detection incidents that require immediate action and this delay may result in the loss or compromise of information.

The ALG generates an alert that notifies designated personnel of the Indicators of Compromise (IOCs) which require real-time alerts. These messages should include a severity level indicator or code as an indicator of the criticality of the incident. These indicators reflect the occurrence of a compromise or a potential compromise.

Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The ALG must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel. Alerts must be sent immediately to designated individuals. Alerts may be sent via NMS, SIEM, Syslog configuration, SNMP trap or notice, or manned console message.

Authoritative sources include USSTRATCOM warning and tactical directives/orders including Fragmentary Order (FRAGO), Communications Tasking Orders (CTOs), IA Vulnerability Notices, Network Defense Tasking Message (NDTM), DOD GIG Tasking Message (DGTM), and Operations Order (OPORD)."
  desc 'check', 'Obtain the list of threats identified by authoritative sources from the ISSM or ISSO. For each threat, ensure a security policy, screen, or filter that denies or mitigates the threat includes the log or syslog option. Verify a log event, SNMP trap, or SNMP notification is generated and sent to be forwarded to, at a minimum, the ISSO and ISSM when threats identified by authoritative sources are detected.

[edit]
show security zones
show security polices

If an alert is not generated that can be forwarded to, at a minimum, the ISSO and ISSM when threats identified by authoritative sources are detected, this is a finding.'
  desc 'fix', 'Configure the Juniper SRX to generate and send a notification or log message that can be forwarded via an event monitoring system (e.g., via Syslog configuration, SNMP trap, manned console message, or other events monitoring system). The NSM, Syslog, or SNMP server must then be configured to send the message.

The following example configures the zone security policy to include the log and/or syslog action in all terms to log packets matching each firewall term to ensure the term results are recorded in the firewall log and Syslog. To get traffic logs from permitted sessions, add "then log session-close" to each policy. To get traffic logs from denied sessions, add "then log session-init" to the policy.

Security policy and security screens:
set security policies from-zone <zone_name> to-zone <zone_name> policy <policy_name> then log

Example:
set security policies from-zone untrust to-zone trust policy default-deny then log session-init'
  impact 0.5
  ref 'DPMS Target Juniper SRX Services Gateway ALG'
  tag check_id: 'C-15746r297304_chk'
  tag severity: 'medium'
  tag gid: 'V-214540'
  tag rid: 'SV-214540r557389_rule'
  tag stig_id: 'JUSX-AG-000147'
  tag gtitle: 'SRG-NET-000392-ALG-000142'
  tag fix_id: 'F-15744r297305_fix'
  tag 'documentable'
  tag legacy: ['SV-80835', 'V-66345']
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
