control 'SV-79785' do
  title 'The DataPower Gateway providing content filtering must generate an alert to, at a minimum, the ISSO and ISSM when threats identified by authoritative sources (e.g., IAVMs or CTOs) are detected.'
  desc "Without an alert, security personnel may be unaware of major detection incidents that require immediate action and this delay may result in the loss or compromise of information.

The ALG generates an alert which notifies designated personnel of the Indicators of Compromise (IOCs) which require real-time alerts. These messages should include a severity level indicator or code as an indicator of the criticality of the incident. These indicators reflect the occurrence of a compromise or a potential compromise.
Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The ALG must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel."
  desc 'check', 'In the DataPower WebGUI, navigate to Administration >> Access >> SNMP Settings. On the "Trap Event Subscriptions" tab, verify the inclusion of Event Subscriptions that are judged to be associated with threats identified by authoritative sources.

If the Event Subscriptions are not present, this is a finding.

On the "Trap and Notification Targets" tab, verify the inclusion of an approved SNMP server.

If no SNMP Server is configured as a Trap and Notification Target, this is a finding.'
  desc 'fix', 'In the DataPower WebGUI, navigate to Administration >> Access >> SNMP Settings. Configure the "Trap Event Subscriptions" tab to include Event Subscriptions that are judged to be associated with threats identified by authoritative sources. Configure the "Trap and Notification Targets" tab to include an approved SNMP server that generates alerts that will be forwarded, at a minimum, to the ISSO and ISSM.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65923r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65295'
  tag rid: 'SV-79785r1_rule'
  tag stig_id: 'WSDP-AG-000114'
  tag gtitle: 'SRG-NET-000392-ALG-000142'
  tag fix_id: 'F-71235r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
