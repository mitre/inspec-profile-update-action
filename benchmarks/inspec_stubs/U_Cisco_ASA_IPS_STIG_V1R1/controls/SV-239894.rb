control 'SV-239894' do
  title 'The Cisco ASA must be configured to send an alert to organization-defined personnel and/or the firewall administrator when DoS incidents are detected.'
  desc %q(Without an alert, security personnel may be unaware of major detection incidents that require immediate action and this delay may result in the loss or compromise of information.

CJCSM 6510.01B, "Cyber Incident Handling Program", lists nine Cyber Incident and Reportable Event Categories. DoD has determined that categories identified by CJCSM 6510.01B Major Indicators (category I, II, IV, and VII detection events) will require an alert when an event is detected.

Alerts messages must include a severity level indicator or code as an indicator of the criticality of the incident. Since these incidents require immediate action, these messages are assigned a critical or level 1 priority/severity, depending on the system's priority schema.

Alerts may be transmitted, for example, telephonically, by electronic mail messages, or by text messaging. The IDPS must either send the alert to a management console that is actively monitored by authorized personnel or use a messaging capability to send the alert directly to designated personnel. The ISSM or ISSO may designate the firewall administrator and/or other authorized personnel to receive the alert within the specified time, validate the alert, and then forward only validated alerts to the ISSM and ISSO.)
  desc 'check', 'Verify email server and email addresses have been defined.

Step 1: Navigate to Policies >> Actions >> Alerts.

Step 2: From the Create Alert drop-down menu, choose Create Email Alert.

Step 3: Verify that the email address is that of organization-defined personnel and/or the firewall administrator.

If the Cisco ASA is not configured to send an alert to organization-defined personnel and/or the firewall administrator when DoS incidents are detected, this is a finding.'
  desc 'fix', 'Configure email server and email addresses to send alerts to organization-defined personnel and/or the firewall administrator.

Step 1: Navigate to Policies >> Actions >> Alerts.

Step 2: From the Create Alert drop-down menu, choose Create Email Alert.

Step 3: Enter a Name for the alert response. In the To field, enter the email addresses where you want to send alerts, separated by commas. In the From field, enter the email address that you want to appear as the sender of the alert. Next to Relay Host, click edit to enter mail server.

Step 4: Click Save.'
  impact 0.5
  ref 'DPMS Target Cisco ASA IPS'
  tag check_id: 'C-43127r665993_chk'
  tag severity: 'medium'
  tag gid: 'V-239894'
  tag rid: 'SV-239894r665995_rule'
  tag stig_id: 'CASA-IP-000560'
  tag gtitle: 'SRG-NET-000392-IDPS-00218'
  tag fix_id: 'F-43086r665994_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
