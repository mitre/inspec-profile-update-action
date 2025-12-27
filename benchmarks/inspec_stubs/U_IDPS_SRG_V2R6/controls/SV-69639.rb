control 'SV-69639' do
  title 'The IDPS must send an alert to, at a minimum, the ISSM and ISSO when denial of service incidents are detected.'
  desc %q(Without an alert, security personnel may be unaware of major detection incidents that require immediate action and this delay may result in the loss or compromise of information.

CJCSM 6510.01B, "Cyber Incident Handling Program", lists nine Cyber Incident and Reportable Event Categories. DoD has determined that categories identified by CJCSM 6510.01B Major Indicators (category I, II, IV, and VII detection events) will require an alert when an event is detected.

Alerts messages must include a severity level indicator or code as an indicator of the criticality of the incident. Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The IDPS must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel. The ISSM or ISSO may designate the system administrator or other authorized personnel to receive the alert within the specified time, validate the alert, then forward only validated alerts to the ISSM and ISSO.)
  desc 'check', 'Verify the IDPS sends an alert to, at a minimum, the ISSM and ISSO when denial of service incidents are detected.

If the IDPS does not send an alert to, at a minimum, the ISSM and ISSO when root level intrusion events when denial of service incidents are detected, this is a finding.'
  desc 'fix', 'Configure the IDPS to send an alert to, at a minimum, the IAM and IAO when denial of service incidents are detected.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-56009r3_chk'
  tag severity: 'medium'
  tag gid: 'V-55393'
  tag rid: 'SV-69639r3_rule'
  tag stig_id: 'SRG-NET-000392-IDPS-00218'
  tag gtitle: 'SRG-NET-000392-IDPS-00218'
  tag fix_id: 'F-60259r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
