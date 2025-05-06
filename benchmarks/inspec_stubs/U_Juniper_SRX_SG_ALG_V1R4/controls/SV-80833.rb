control 'SV-80833' do
  title 'The Juniper SRX Services Gateway Firewall must generate an alert to, at a minimum, the ISSO and ISSM when unusual/unauthorized activities or conditions are detected during continuous monitoring of communications traffic as it traverses inbound or outbound across internal security boundaries.'
  desc "Without an alert, security personnel may be unaware of major detection incidents that require immediate action and this delay may result in the loss or compromise of information.

Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

In accordance with CCI-001242, the ALG which provides content inspection services is a real-time intrusion detection system. These systems must generate an alert when detection events from real-time monitoring occur as required by CCI-2262 and CCI-2261. Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The ALG must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel. Alerts must be sent immediately to designated individuals. Alerts may be sent via NMS, SIEM, Syslog configuration, SNMP trap or notice, or manned console message.

Unusual/unauthorized activities or conditions may include large file transfers, long-time persistent connections, unusual protocols and ports in use, and attempted communications with suspected malicious external addresses."
  desc 'check', 'For each zone, verify a log event, SNMP trap, or SNMP notification is generated and sent to be forwarded to, at a minimum, the ISSO and ISSM when unusual/unauthorized activities or conditions are detected during continuous monitoring of communications traffic as it traverses inbound or outbound across internal security boundaries. 

[edit]
show security zones
show security polices

If each inbound and outbound zone policy does not generate an alert that can be forwarded to, at a minimum, the ISSO and ISSM when unusual/unauthorized activities or conditions are detected during continuous monitoring of communications traffic as it traverses inbound or outbound across internal security boundaries, this is a finding.'
  desc 'fix', 'Configure the Juniper SRX to generate and send a notification or log message immediately that can be forwarded via an event monitoring system (e.g., via Syslog configuration, SNMP trap, manned console message, or other events monitoring system). The NSM, Syslog, or SNMP server must then be configured to send the message.

The following example configures the zone security policy to include the log and/or syslog action in all terms to log packets matching each firewall term to ensure the term results are recorded in the firewall log and Syslog. To get traffic logs from permitted sessions, add "then log session-close" to each policy. To get traffic logs from denied sessions, add "then log session-init" to the policy.

Security policy and security screens:
set security policies from-zone <zone_name> to-zone <zone_name> policy <policy_name> then log

Example:
set security policies from-zone untrust to-zone trust policy default-deny then log session-init'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG ALG'
  tag check_id: 'C-66989r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66343'
  tag rid: 'SV-80833r1_rule'
  tag stig_id: 'JUSX-AG-000146'
  tag gtitle: 'SRG-NET-000392-ALG-000141'
  tag fix_id: 'F-72419r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
