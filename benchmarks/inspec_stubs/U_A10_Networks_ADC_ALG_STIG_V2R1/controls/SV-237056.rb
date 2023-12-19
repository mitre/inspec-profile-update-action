control 'SV-237056' do
  title 'The A10 Networks ADC must enable logging of Denial of Service (DoS) attacks.'
  desc 'Without an alert, security personnel may be unaware of major detection incidents that require immediate action, and this delay may result in the loss or compromise of information. CJCSM 6510.01B, "Cyber Incident Handling Program", lists nine Cyber Incident and Reportable Event Categories. DoD has determined that categories identified by CJCSM 6510.01B Major Indicators (category 1, 2, 4, or 7 detection events) will require an alert when an event is detected. Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The device must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel.

The A10 Networks ADC must be configured to generate a log message when IP anomalies and DoS attacks are detected.'
  desc 'check', 'Review the device configuration.

The following command displays the device configuration and filters the output on the string "log":
show run | inc log

If the output does not include the command "system attack log", this is a finding.'
  desc 'fix', 'The following command enables logging of DDoS attacks:
system attack log'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC ALG'
  tag check_id: 'C-40275r639613_chk'
  tag severity: 'medium'
  tag gid: 'V-237056'
  tag rid: 'SV-237056r639615_rule'
  tag stig_id: 'AADC-AG-000117'
  tag gtitle: 'SRG-NET-000392-ALG-000148'
  tag fix_id: 'F-40238r639614_fix'
  tag 'documentable'
  tag legacy: ['SV-82501', 'V-68011']
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
