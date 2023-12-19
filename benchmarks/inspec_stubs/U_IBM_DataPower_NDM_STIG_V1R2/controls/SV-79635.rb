control 'SV-79635' do
  title 'The DataPower Gateway must generate an immediate alert when allocated audit record storage volume reaches 75% of repository maximum audit record storage capacity.'
  desc 'If security personnel are not notified immediately upon storage volume utilization reaching 75%, they are unable to plan for storage capacity expansion. This could lead to the loss of audit information. Note that while the network device must generate the alert, notification may be done by a management server.'
  desc 'check', 'Production configuration (off-box logging):
Using the DataPower WebGUI, navigate to Objects >> Logging Configuration >> Log Target. On the main tab, verify that the correct Target Type and Log Format are selected. Confirm that the remote host and port of an organizationally approved logging server are designated. Confirm that all additional parameters are chosen according to your requirements. Confirm that the status of the log target is displayed as [up] alongside the Log Target heading at the top of the page.

To test 75 percent notification: Set the allowed maximum file size to a minimum value, e.g., 250k. Restart the DataPower Gateway several times to generate sufficient audit log messages to fill up the off-box audit log file. Confirm that notification is received at 75 percent of capacity. If it is not, this is a finding.'
  desc 'fix', 'Production configuration (off-box logging):
Off-box logging provides optimal storage size flexibility and log size notification capability.
Using the DataPower WebGUI, navigate to Objects >> Logging Configuration >> Log Target. On the main tab, choose a Target Type, e.g., syslog-tcp, and a Log Format. Specify the remote host and port of the logging server. Enter other parameters according to your requirements, e.g., SSL security.

On the Event Subscriptions tab, add an Event Subscription. Select "audit" as the Event Category. Select a minimum Event Priority, e.g., "error”. Click "Apply" >>Click "Apply” >> Click "Save Configuration." Confirm that the status of the log target is displayed as [up] alongside the Log Target heading at the top of the page.

It is the responsibility of the target log server to provide an alert when the audit log has reached 75 percent of capacity.'
  impact 0.3
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65773r1_chk'
  tag severity: 'low'
  tag gid: 'V-65145'
  tag rid: 'SV-79635r1_rule'
  tag stig_id: 'WSDP-NM-000096'
  tag gtitle: 'SRG-APP-000359-NDM-000294'
  tag fix_id: 'F-71085r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
