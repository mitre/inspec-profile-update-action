control 'SV-79783' do
  title 'The DataPower Gateway providing content filtering must send an alert to, at a minimum, the ISSO and ISSM when detection events occur.'
  desc "Without an alert, security personnel may be unaware of major detection incidents that require immediate action and this delay may result in the loss or compromise of information.

Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

In accordance with CCI-001242, the ALG which provides content inspection services are a real-time intrusion detection system. These systems must generate an alert when detection events from real-time monitoring occur. Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The ALG must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel."
  desc 'check', 'In the DataPower web interface, navigate to Administration >> Access >> SNMP Settings. Verify that the desired event codes are included on the "Trap Event Subscriptions" tab.

Type "Log Target" in to the Search bar >> Select "Log Targets" from the results list >> Select the desired Log Target >> Verify that the desired event codes are included in the Event Subscriptions tab.

If no Log Target is configured or the assigned event codes are not included, this is a finding.'
  desc 'fix', 'In the DataPower WebGUI, navigate to Administration >> Access >> SNMP Settings. Configure the "Trap Event Subscriptions" tab to include Event Subscriptions that are judged to be associated with detection incidents. Configure the "Trap and Notification Targets" tab to include an SNMP server.

The administrator can also configure a Log Target to send event information to other logging/monitoring solutions, including Syslog. 

To configure a Syslog Log Target, type "Log Target" in to the Search bar >> Select "Log Targets" from the results list >> Click Add >> Configure a Log Target of type "syslog" >> Configure specific event subscriptions to be sent to the Syslog Server.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65921r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65293'
  tag rid: 'SV-79783r1_rule'
  tag stig_id: 'WSDP-AG-000113'
  tag gtitle: 'SRG-NET-000392-ALG-000141'
  tag fix_id: 'F-71233r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
