control 'SV-69631' do
  title 'The IDSP must send an alert to, at a minimum, the ISSM and ISSO when intrusion detection events are detected which indicate a compromise or potential for compromise.'
  desc 'Without an alert, security personnel may be unaware of intrusion detection incidents that require immediate action and this delay may result in the loss or compromise of information.

In accordance with CCI-001242, the IDPS is a real-time intrusion detection system. These systems must generate an alert when detection events from real-time monitoring occur. Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The IDPS must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel. The ISSM or ISSO may designate the system administrator or other authorized personnel to receive the alert within the specified time, validate the alert, then forward only validated alerts to the ISSM and ISSO.'
  desc 'check', 'Verify the IDPS sends an alert to, at a minimum, the ISSM and ISSO when intrusion detection events are detected which indicate a compromise or potential for compromise.

If the IDPS does not send an alert to, at a minimum, the ISSO and ISSM when intrusion detection events are detected which indicate a compromise or potential for compromise, this is a finding.'
  desc 'fix', 'Configure the IDPS to send an alert to, at a minimum, the ISSO and ISSM when intrusion detection events are detected which indicate a compromise or potential for compromise.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-56001r3_chk'
  tag severity: 'medium'
  tag gid: 'V-55385'
  tag rid: 'SV-69631r3_rule'
  tag stig_id: 'SRG-NET-000392-IDPS-00214'
  tag gtitle: 'SRG-NET-000392-IDPS-00214'
  tag fix_id: 'F-60251r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
