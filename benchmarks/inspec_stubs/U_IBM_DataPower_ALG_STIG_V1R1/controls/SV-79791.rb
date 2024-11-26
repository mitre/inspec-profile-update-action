control 'SV-79791' do
  title 'The DataPower Gateway providing content filtering must generate an alert to, at a minimum, the ISSO and ISSM when denial of service incidents are detected.'
  desc %q(Without an alert, security personnel may be unaware of major detection incidents that require immediate action and this delay may result in the loss or compromise of information.

The ALG generates an alert which notifies designated personnel of the Indicators of Compromise (IOCs) which require real-time alerts. These messages should include a severity level indicator or code as an indicator of the criticality of the incident. These indicators reflect the occurrence of a compromise or a potential compromise.
Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

CJCSM 6510.01B, "Cyber Incident Handling Program", lists nine Cyber Incident and Reportable Event Categories. DoD has determined that categories identified by CJCSM 6510.01B Major Indicators (category 1, 2, 4, or 7 detection events) will require an alert when an event is detected.

Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The ALG must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel.)
  desc 'check', 'From the WebGUI, go to Objects >> Logging Configuration>> Log Target. On the Main tab, SNMP should be selected. On the Event Subscriptions tab, confirm that there is an event subscription where Event Category = multistep and Minimum Event Priority = error.

In the DataPower WebGUI, navigate to Administration >> Access >> SNMP Settings. Verify that the "Trap and Notification Targets" tab includes an approved SNMP server that generates alerts that will be forwarded, at a minimum, to the ISSO and ISSM.

If no SNMP server is configured as a Log Target, this is a finding.'
  desc 'fix', 'From the WebGUI, go to Objects >> Logging Configuration >> Log Target. On the Main tab, select SNMP. On the Event Subscriptions tab add an event subscription where Event Category = multistep and Minimum Event Priority = error.

Configure the DataPower Gateway to, upon receipt of a multistep error message, send a notification to an authorized SNMP server. That server must be configured to, at a minimum, send an alert to the ISSO and ISSM.

In the DataPower WebGUI, navigate to Administration >> Access >> SNMP Settings. Configure the "Trap and Notification Targets" tab to include an approved SNMP server that generates alerts that will be forwarded, at a minimum, to the ISSO and ISSM.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65929r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65301'
  tag rid: 'SV-79791r1_rule'
  tag stig_id: 'WSDP-AG-000117'
  tag gtitle: 'SRG-NET-000392-ALG-000148'
  tag fix_id: 'F-71241r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
