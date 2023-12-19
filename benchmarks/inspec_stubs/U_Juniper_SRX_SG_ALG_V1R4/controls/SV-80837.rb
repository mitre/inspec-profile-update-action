control 'SV-80837' do
  title 'The Juniper SRX Services Gateway Firewall must generate an alert that can be forwarded to, at a minimum, the ISSO and ISSM when DoS incidents are detected.'
  desc %q(Without an alert, security personnel may be unaware of major detection incidents that require immediate action and this delay may result in the loss or compromise of information.

The ALG generates an alert that notifies designated personnel of the Indicators of Compromise (IOCs) which require real-time alerts. These messages should include a severity level indicator or code as an indicator of the criticality of the incident. These indicators reflect the occurrence of a compromise or a potential compromise.

Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

CJCSM 6510.01B, "Cyber Incident Handling Program", lists nine Cyber Incident and Reportable Event Categories. DoD has determined that categories identified by CJCSM 6510.01B Major Indicators (category 1, 2, 4, or 7 detection events) will require an alert when an event is detected.

Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The ALG must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel.)
  desc 'check', 'Verify a security policy with an associated screen that denies or mitigates the threat of DoS attacks includes the log or syslog option. Verify a log event, SNMP trap, or SNMP notification is generated and sent to be forwarded to, at a minimum, the ISSO and ISSM when threats identified by authoritative sources are detected.

[edit]
show security zones
show security polices

If an alert is not generated that can be forwarded to, at a minimum, the ISSO and ISSM when DoS incidents are detected, this is a finding.'
  desc 'fix', 'Configure the Juniper SRX to generate for DoS attacks detected in CCI-002385. DoS attacks are detected using screens. The alert sends a notification or log message that can be forwarded via an event monitoring system (e.g., via Syslog configuration, SNMP trap, manned console message, or other events monitoring system). The NSM, Syslog, or SNMP server must then be configured to send the message.

The following example configures the zone security policy to include the log and/or syslog action in all terms to log packets matching each firewall term to ensure the term results are recorded in the firewall log and Syslog. To get traffic logs from permitted sessions, add "then log session-close" to each policy. To get traffic logs from denied sessions, add "then log session-init" to the policy.

Apply policy or screen to a zone example:

set security zones security-zone trust interfaces ge-0/0/2.0
set security zones security-zone untrust screen untrust-screen
set security policies from-zone untrust to-zone trust policy default-deny then log session-init'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG ALG'
  tag check_id: 'C-66993r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66347'
  tag rid: 'SV-80837r1_rule'
  tag stig_id: 'JUSX-AG-000150'
  tag gtitle: 'SRG-NET-000392-ALG-000148'
  tag fix_id: 'F-72423r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
