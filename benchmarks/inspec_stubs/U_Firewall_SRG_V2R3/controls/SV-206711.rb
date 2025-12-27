control 'SV-206711' do
  title 'The firewall must generate an alert that can be forwarded to, at a minimum, the ISSO and ISSM when denial-of-service (DoS) incidents are detected.'
  desc %q(Without an alert, security personnel may be unaware of major detection incidents that require immediate action, and this delay may result in the loss or compromise of information.

The firewall generates an alert that notifies designated personnel of the Indicators of Compromise (IOCs), which require real-time alerts. These messages should include a severity level indicator or code as an indicator of the criticality of the incident. These indicators reflect the occurrence of a compromise or a potential compromise.

Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

CJCSM 6510.01B, "Cyber Incident Handling Program", lists nine Cyber Incident and Reportable Event Categories. DoD has determined that categories identified by CJCSM 6510.01B Major Indicators (category 1, 2, 4, or 7 detection events) will require an alert when an event is detected.

Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The firewall must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel.)
  desc 'check', 'If a network device such as the events, network management, or SNMP server is configured to send an alert when DoS incidents are detected, this is not a finding.

Verify the firewall is configured to send an alert via instant message, email, SNMP, or another authorized method to the ISSO, ISSM, and other identified personnel when DoS incidents are detected.

If the firewall is not configured to send an alert via an approved and immediate method when DoS incidents are detected, this is a finding.'
  desc 'fix', 'Configure the firewall (or another network device) to send an alert via instant message, email, or another authorized method to the ISSO and ISSM and other identified personnel when DoS incidents are detected.'
  impact 0.3
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6968r297912_chk'
  tag severity: 'low'
  tag gid: 'V-206711'
  tag rid: 'SV-206711r855869_rule'
  tag stig_id: 'SRG-NET-000392-FW-000042'
  tag gtitle: 'SRG-NET-000392'
  tag fix_id: 'F-6968r297913_fix'
  tag 'documentable'
  tag legacy: ['SV-94195', 'V-79489']
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
