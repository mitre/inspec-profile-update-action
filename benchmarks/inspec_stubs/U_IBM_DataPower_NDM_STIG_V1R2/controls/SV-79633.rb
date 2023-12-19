control 'SV-79633' do
  title 'The DataPower Gateway must allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc 'In order to ensure network devices have a sufficient storage capacity in which to write the audit logs, they need to be able to allocate audit record storage capacity. The task of allocating audit record storage capacity is usually performed during initial device setup if it is modifiable. 

The value for the organization-defined audit record storage requirement will depend on the amount of storage available on the network device, the anticipated volume of logs, the frequency of transfer from the network device to centralized log servers, and other factors.'
  desc 'check', 'Development configuration (on-box logging): Using the DataPower web interface, navigate to Objects >> Logging Configuration >> Audit Log Settings. Verify that the desired Log Size, Number of Rotations has resulted in "[up]" status displayed after the "Audit Log Settings" heading at the top of page. In the WebGUI, navigate to Status >> View Logs >> System Logs. Ensure the following event message is not displayed: 0x82400067 Audit log space low - using audit reserve space.

If this message appears, it is a finding.

Production configuration (off-box logging)
Using the DataPower WebGUI, navigate to Objects >> Logging Configuration >> Log Target. On the main tab, verify that the correct Target Type and Log Format are selected. Confirm that the remote host and port of an organizationally approved logging server are designated. Confirm that all additional parameters are chosen according to your requirements. Confirm that the status of the log target is displayed as [up] alongside the Log Target heading at the top of the page.

If the status is not up, this is a finding.'
  desc 'fix', 'Development configuration (on-box logging):
Using the DataPower WebGUI, navigate to Objects >> Logging Configuration >> Audit Log Settings. Specify the desired Log Size, Number of Rotations, and audit level. Press Apply then Save Configuration. (Maximum available log space is approximately 50GB - less space consumed by other data on the device.) 

Production configuration (off-box logging):
Using the DataPower WebGUI, navigate to Objects >> Logging Configuration >> Log Target. On the main tab, choose a Target Type, e.g., syslog-tcp, and a Log Format. Specify the remote host and port of the logging server. Enter other parameters according to your requirements, e.g., SSL security.

On the Event Subscriptions tab, add an Event Subscription. Select "audit" as the Event Category. Select a minimum Event Priority, e.g., "error. Click "Apply" >> Click "Apply" >> Click "Save Configuration". Confirm that the status of the log target is displayed as [up] alongside the Log Target heading at the top of the page.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65771r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65143'
  tag rid: 'SV-79633r1_rule'
  tag stig_id: 'WSDP-NM-000095'
  tag gtitle: 'SRG-APP-000357-NDM-000293'
  tag fix_id: 'F-71083r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
