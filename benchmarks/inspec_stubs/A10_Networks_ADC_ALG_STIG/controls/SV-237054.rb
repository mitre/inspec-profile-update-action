control 'SV-237054' do
  title 'The A10 Networks ADC must enable logging for packet anomaly events.'
  desc "Without an alert, security personnel may be unaware of major detection incidents that require immediate action and this delay may result in the loss or compromise of information. Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

These systems must generate an alert when detection events from real-time monitoring occur. Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The device must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel.

The A10 Networks ADC must be configured to generate a log message when IP anomalies are detected."
  desc 'check', 'Review the device configuration.

The following command displays the device configuration and filters the output on the string "log":
show run | inc log

If the output does not include the command "system anomaly log", this is a finding.'
  desc 'fix', 'The following command enables logging of packet anomaly events:
system anomaly log'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC ALG'
  tag check_id: 'C-40273r639607_chk'
  tag severity: 'medium'
  tag gid: 'V-237054'
  tag rid: 'SV-237054r639609_rule'
  tag stig_id: 'AADC-AG-000113'
  tag gtitle: 'SRG-NET-000392-ALG-000141'
  tag fix_id: 'F-40236r639608_fix'
  tag 'documentable'
  tag legacy: ['SV-82499', 'V-68009']
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
