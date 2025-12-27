control 'SV-242205' do
  title 'The TPS must send an alert to, at a minimum, the ISSM and ISSO when intrusion detection events are detected which indicate a compromise or potential for compromise.'
  desc 'Without an alert, security personnel may be unaware of intrusion detection incidents that require immediate action and this delay may result in the loss or compromise of information.

In accordance with CCI-001242, the TPS is a real-time intrusion detection system. These systems must generate an alert when detection events from real-time monitoring occur. Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The IDPS must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel. The ISSM or ISSO may designate the system administrator or other authorized personnel to receive the alert within the specified time, validate the alert, then forward only validated alerts to the ISSM and ISSO. The TPS must generate an alert to, at a minimum, the ISSM and ISSO when root level intrusion events which provide unauthorized privileged access are detected.

'
  desc 'check', '1. In the Trend Micro SMS, navigate to "Profiles" and "Shared Settings". 
2. Under "Action Sets", if a group email address for the ISSO is not added for both the "Block+Notify" and "Block+Notify+Trace", this is a finding.'
  desc 'fix', '1. In the Trend Micro SMS, navigate to "Profiles" and "Shared Settings". 
2. Under "Action Sets": 
   a. Select "Block+Notify" and Edit. 
   b. Select Notifications, click "add", and add an email address for the ISSO and the aggregation time in minutes. 
   c. Select "Finish".'
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45480r710156_chk'
  tag severity: 'medium'
  tag gid: 'V-242205'
  tag rid: 'SV-242205r710158_rule'
  tag stig_id: 'TIPP-IP-000430'
  tag gtitle: 'SRG-NET-000392-IDPS-00214'
  tag fix_id: 'F-45438r710157_fix'
  tag satisfies: ['SRG-NET-000392-IDPS-00214', 'SRG-NET-000392-IDPS-00216', 'SRG-NET-000392-IDPS-00218']
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
